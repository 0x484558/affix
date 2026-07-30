use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(windows)]
use std::mem::size_of;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
use std::thread;
use tracing::warn;
#[cfg(windows)]
use windows::Win32::Foundation::GetLastError;
#[cfg(windows)]
use windows_sys::Win32::System::SystemInformation::{
    CacheUnified, CpuSetInformation, GROUP_AFFINITY, GetLogicalProcessorInformationEx,
    GetSystemCpuSetInformation, RelationCache, SYSTEM_CPU_SET_INFORMATION,
    SYSTEM_CPU_SET_INFORMATION_ALLOCATED, SYSTEM_CPU_SET_INFORMATION_ALLOCATED_TO_TARGET_PROCESS,
    SYSTEM_CPU_SET_INFORMATION_PARKED, SYSTEM_CPU_SET_INFORMATION_REALTIME,
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuSetEntry {
    pub id: u32,
    pub group: u16,
    pub logical_index: usize,
    pub core_index: usize,
    pub last_level_cache_index: usize,
    pub numa_node: usize,
    pub efficiency_class: u8,
    pub cache: bool,
    pub parked: bool,
    pub allocated_to_other: bool,
    pub realtime: bool,
}

pub struct CpuTopology {
    pub entries: Vec<CpuSetEntry>,
}

impl CpuTopology {
    pub fn read_or_fallback() -> Result<Self, String> {
        match read_cpu_sets() {
            Ok(entries) if !entries.is_empty() => Ok(Self { entries }),
            Ok(_) => Ok(Self {
                entries: fallback_logical_entries(),
            }),
            Err(err) => {
                warn!(error = %err, "falling back to homogeneous CPU topology");
                Ok(Self {
                    entries: fallback_logical_entries(),
                })
            }
        }
    }
}

#[cfg(windows)]
pub fn read_cpu_sets() -> Result<Vec<CpuSetEntry>, String> {
    let mut returned_length = 0u32;
    let ok = unsafe {
        GetSystemCpuSetInformation(
            std::ptr::null_mut(),
            0,
            &mut returned_length,
            std::ptr::null_mut(),
            0,
        )
    };
    if ok != 0 || returned_length == 0 {
        return Err(
            "GetSystemCpuSetInformation did not report a required buffer length".to_string(),
        );
    }

    let mut buffer = vec![0u8; returned_length as usize];
    let ok = unsafe {
        GetSystemCpuSetInformation(
            buffer.as_mut_ptr() as *mut SYSTEM_CPU_SET_INFORMATION,
            returned_length,
            &mut returned_length,
            std::ptr::null_mut(),
            0,
        )
    };
    if ok == 0 {
        return Err(format!(
            "GetSystemCpuSetInformation failed with Windows error {}",
            unsafe { GetLastError().0 }
        ));
    }

    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset + size_of::<SYSTEM_CPU_SET_INFORMATION>() <= returned_length as usize {
        let info = unsafe { &*(buffer.as_ptr().add(offset) as *const SYSTEM_CPU_SET_INFORMATION) };
        if info.Size == 0 {
            return Err("GetSystemCpuSetInformation returned a zero-sized entry".to_string());
        }
        if info.Type == CpuSetInformation {
            let cpu_set = unsafe { info.Anonymous.CpuSet };
            let flags = unsafe { cpu_set.Anonymous1.AllFlags };
            let allocated = flags & SYSTEM_CPU_SET_INFORMATION_ALLOCATED as u8 != 0;
            let allocated_to_target =
                flags & SYSTEM_CPU_SET_INFORMATION_ALLOCATED_TO_TARGET_PROCESS as u8 != 0;
            let logical_index = cpu_set.LogicalProcessorIndex as usize;
            if cpu_set.Group == 0 && logical_index >= usize::BITS as usize {
                return Err(format!(
                    "logical processor index {logical_index} cannot fit in process affinity mask"
                ));
            }
            entries.push(CpuSetEntry {
                id: cpu_set.Id,
                group: cpu_set.Group,
                logical_index,
                core_index: cpu_set.CoreIndex as usize,
                last_level_cache_index: cpu_set.LastLevelCacheIndex as usize,
                numa_node: cpu_set.NumaNodeIndex as usize,
                efficiency_class: cpu_set.EfficiencyClass,
                cache: false,
                parked: flags & SYSTEM_CPU_SET_INFORMATION_PARKED as u8 != 0,
                allocated_to_other: allocated && !allocated_to_target,
                realtime: flags & SYSTEM_CPU_SET_INFORMATION_REALTIME as u8 != 0,
            });
        }
        offset += info.Size as usize;
    }

    let c_caches = match detect_c_cache_affinities() {
        Ok(caches) => caches,
        Err(err) => {
            warn!(
                error = %err,
                "failed to read C cache topology; treating C selector as unavailable"
            );
            Vec::new()
        }
    };
    for entry in &mut entries {
        entry.cache = c_caches
            .iter()
            .any(|cache| cache.contains(entry.group, entry.logical_index));
    }

    entries.sort_by_key(|entry| (entry.logical_index, entry.id));
    Ok(entries)
}

#[cfg(target_os = "linux")]
pub fn read_cpu_sets() -> Result<Vec<CpuSetEntry>, String> {
    let cpu_ids = online_cpu_ids().unwrap_or_else(|err| {
        warn!(error = %err, "failed to read Linux online CPU list; using available_parallelism");
        (0..fallback_logical_entries().len()).collect()
    });
    if cpu_ids.is_empty() {
        return Err("Linux online CPU list is empty".to_string());
    }

    let mut scored = Vec::new();
    for cpu in cpu_ids {
        let cpu_path = PathBuf::from(format!("/sys/devices/system/cpu/cpu{cpu}"));
        let score = read_cpu_score(cpu, &cpu_path);
        let island = read_linux_cpu_island_signature(&cpu_path);
        scored.push((cpu, cpu_path, score, island));
    }

    let island_indexes = linux_island_index_map(
        scored
            .iter()
            .filter_map(|(_, _, _, island)| island.as_deref()),
    );
    let classes = efficiency_class_map(scored.iter().filter_map(|(_, _, score, _)| *score));
    let has_scores = !classes.is_empty();
    let mut entries = Vec::with_capacity(scored.len());
    for (cpu, cpu_path, score, island) in scored {
        let efficiency_class = score
            .and_then(|score| classes.get(&score).copied())
            .unwrap_or(0);
        entries.push(CpuSetEntry {
            id: cpu as u32,
            group: 0,
            logical_index: cpu,
            core_index: read_usize(cpu_path.join("topology/core_id")).unwrap_or(cpu),
            last_level_cache_index: island
                .as_ref()
                .and_then(|island| island_indexes.get(island).copied())
                .unwrap_or(0),
            numa_node: read_numa_node(&cpu_path).unwrap_or(0),
            efficiency_class,
            cache: false,
            parked: false,
            allocated_to_other: false,
            realtime: false,
        });
    }

    if !has_scores {
        warn!(
            "Linux CPU topology has no hybrid core hints; treating P/E/LPE selectors as homogeneous"
        );
    }
    entries.sort_by_key(|entry| (entry.logical_index, entry.id));
    Ok(entries)
}

pub fn fallback_logical_entries() -> Vec<CpuSetEntry> {
    let count = thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    (0..count)
        .map(|index| CpuSetEntry {
            id: index as u32,
            group: 0,
            logical_index: index,
            core_index: index,
            last_level_cache_index: 0,
            numa_node: 0,
            efficiency_class: 0,
            cache: false,
            parked: false,
            allocated_to_other: false,
            realtime: false,
        })
        .collect()
}

pub fn efficiency_classes(entries: &[&CpuSetEntry]) -> Vec<u8> {
    let mut classes: Vec<u8> = entries.iter().map(|entry| entry.efficiency_class).collect();
    classes.sort_unstable();
    classes.dedup();
    classes
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct L3CacheAffinity {
    pub group: u16,
    pub mask: usize,
    pub cache_size: u32,
}

impl L3CacheAffinity {
    pub fn contains(&self, group: u16, logical_index: usize) -> bool {
        group == self.group
            && logical_index < usize::BITS as usize
            && (self.mask & (1usize << logical_index)) != 0
    }

    pub fn processor_count(&self) -> u32 {
        self.mask.count_ones()
    }

    pub fn lowest_logical_index(&self) -> u32 {
        self.mask.trailing_zeros()
    }
}

pub fn detect_c_cache_affinities() -> Result<Vec<L3CacheAffinity>, String> {
    let l3_caches = read_l3_cache_affinities()?;
    if !is_c_cache_candidate(&l3_caches) {
        return Ok(Vec::new());
    }

    Ok(select_c_l3_cache_affinities(&l3_caches))
}

pub fn is_c_cache_candidate(caches: &[L3CacheAffinity]) -> bool {
    if is_amd_x3d_cache_candidate_processor() {
        return true;
    }
    // For non-AMD systems, detect if there is a "large cache like unique CCD"
    // meaning asymmetrical L3 cache sizes where one CCD/core group has a strictly larger L3 cache size.
    let sizes: Vec<u32> = caches
        .iter()
        .filter(|c| c.cache_size > 0 && c.mask != 0)
        .map(|c| c.cache_size)
        .collect();
    if sizes.len() > 1 {
        let max = *sizes.iter().max().unwrap_or(&0);
        let min = *sizes.iter().min().unwrap_or(&0);
        max > min
    } else {
        false
    }
}

pub fn select_c_l3_cache_affinities(caches: &[L3CacheAffinity]) -> Vec<L3CacheAffinity> {
    let Some(cache) = caches
        .iter()
        .copied()
        .filter(|cache| cache.cache_size != 0 && cache.mask != 0)
        .max_by_key(|cache| {
            (
                cache.cache_size,
                cache.processor_count(),
                std::cmp::Reverse(cache.group),
                std::cmp::Reverse(cache.lowest_logical_index()),
            )
        })
    else {
        return Vec::new();
    };

    vec![cache]
}

#[cfg(windows)]
pub fn read_l3_cache_affinities() -> Result<Vec<L3CacheAffinity>, String> {
    let mut returned_length = 0u32;
    let ok = unsafe {
        GetLogicalProcessorInformationEx(RelationCache, std::ptr::null_mut(), &mut returned_length)
    };
    if ok != 0 || returned_length == 0 {
        return Err(
            "GetLogicalProcessorInformationEx(RelationCache) did not report a required buffer length"
                .to_string(),
        );
    }

    let mut buffer = vec![0u8; returned_length as usize];
    let ok = unsafe {
        GetLogicalProcessorInformationEx(
            RelationCache,
            buffer.as_mut_ptr() as *mut SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
            &mut returned_length,
        )
    };
    if ok == 0 {
        return Err(format!(
            "GetLogicalProcessorInformationEx(RelationCache) failed with Windows error {}",
            unsafe { GetLastError().0 }
        ));
    }

    let mut caches = Vec::new();
    let mut offset = 0usize;
    while offset < returned_length as usize {
        if offset + size_of::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>() > returned_length as usize
        {
            return Err(
                "GetLogicalProcessorInformationEx(RelationCache) returned a truncated entry"
                    .to_string(),
            );
        }

        let info = unsafe {
            &*(buffer.as_ptr().add(offset) as *const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)
        };
        if info.Size == 0 {
            return Err(
                "GetLogicalProcessorInformationEx(RelationCache) returned a zero-sized entry"
                    .to_string(),
            );
        }
        if offset + info.Size as usize > returned_length as usize {
            return Err(
                "GetLogicalProcessorInformationEx(RelationCache) entry exceeds returned buffer"
                    .to_string(),
            );
        }

        if info.Relationship == RelationCache {
            let cache = unsafe { &info.Anonymous.Cache };
            if cache.Level == 3 && cache.Type == CacheUnified {
                let group_count = cache.GroupCount as usize;
                let expected_size = size_of::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>()
                    + group_count
                        .saturating_sub(1)
                        .saturating_mul(size_of::<GROUP_AFFINITY>());
                if group_count == 0 || (info.Size as usize) < expected_size {
                    return Err(
                        "GetLogicalProcessorInformationEx(RelationCache) returned an invalid cache group count"
                            .to_string(),
                    );
                }

                let group_masks = unsafe { cache.Anonymous.GroupMasks.as_ptr() };
                for index in 0..group_count {
                    let group_mask = unsafe { *group_masks.add(index) };
                    if group_mask.Mask != 0 {
                        caches.push(L3CacheAffinity {
                            group: group_mask.Group,
                            mask: group_mask.Mask,
                            cache_size: cache.CacheSize,
                        });
                    }
                }
            }
        }

        offset += info.Size as usize;
    }

    Ok(caches)
}

#[cfg(target_os = "linux")]
pub fn read_l3_cache_affinities() -> Result<Vec<L3CacheAffinity>, String> {
    Ok(Vec::new())
}

#[cfg(target_arch = "x86_64")]
pub fn is_amd_x3d_cache_candidate_processor() -> bool {
    let Some((vendor, display_family, brand)) = x86_processor_identity() else {
        return false;
    };

    vendor == *b"AuthenticAMD"
        && matches!(display_family, 0x19 | 0x1a)
        && processor_brand_contains_x3d(&brand)
}

#[cfg(not(target_arch = "x86_64"))]
pub fn is_amd_x3d_cache_candidate_processor() -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
fn x86_processor_identity() -> Option<([u8; 12], u32, [u8; 48])> {
    use std::arch::x86_64::__cpuid;

    let leaf0 = __cpuid(0);
    if leaf0.eax < 1 {
        return None;
    }

    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&leaf0.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&leaf0.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&leaf0.ecx.to_le_bytes());

    let leaf1 = __cpuid(1);
    let brand = read_x86_processor_brand()?;
    Some((vendor, display_family_from_cpuid_eax(leaf1.eax), brand))
}

#[cfg(target_arch = "x86_64")]
fn read_x86_processor_brand() -> Option<[u8; 48]> {
    use std::arch::x86_64::__cpuid;

    let max_extended_leaf = __cpuid(0x8000_0000).eax;
    if max_extended_leaf < 0x8000_0004 {
        return None;
    }

    let mut brand = [0u8; 48];
    for (index, leaf) in (0x8000_0002..=0x8000_0004).enumerate() {
        let result = __cpuid(leaf);
        let offset = index * 16;
        brand[offset..offset + 4].copy_from_slice(&result.eax.to_le_bytes());
        brand[offset + 4..offset + 8].copy_from_slice(&result.ebx.to_le_bytes());
        brand[offset + 8..offset + 12].copy_from_slice(&result.ecx.to_le_bytes());
        brand[offset + 12..offset + 16].copy_from_slice(&result.edx.to_le_bytes());
    }

    Some(brand)
}

pub fn processor_brand_contains_x3d(brand: &[u8]) -> bool {
    String::from_utf8_lossy(brand)
        .to_ascii_uppercase()
        .contains("X3D")
}

#[cfg(target_arch = "x86_64")]
fn display_family_from_cpuid_eax(eax: u32) -> u32 {
    let base_family = (eax >> 8) & 0x0f;
    let extended_family = (eax >> 20) & 0xff;
    if base_family == 0x0f {
        base_family + extended_family
    } else {
        base_family
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CpuIslandKey {
    pub group: u16,
    pub numa_node: usize,
    pub last_level_cache_index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuIslandCandidate {
    pub key: CpuIslandKey,
    pub count: usize,
    pub max_logical_index: usize,
    pub shares_with_higher_efficiency: bool,
}

pub fn cpu_island_key(entry: &CpuSetEntry) -> CpuIslandKey {
    CpuIslandKey {
        group: entry.group,
        numa_node: entry.numa_node,
        last_level_cache_index: entry.last_level_cache_index,
    }
}

pub fn choose_efficiency_island(
    efficient_candidates: &[&CpuSetEntry],
    higher_efficiency_pool: &[&CpuSetEntry],
) -> Option<CpuIslandCandidate> {
    let mut islands: BTreeMap<CpuIslandKey, CpuIslandCandidate> = BTreeMap::new();
    for entry in efficient_candidates {
        let key = cpu_island_key(entry);
        let island = islands.entry(key).or_insert(CpuIslandCandidate {
            key,
            count: 0,
            max_logical_index: 0,
            shares_with_higher_efficiency: false,
        });
        island.count += 1;
        island.max_logical_index = island.max_logical_index.max(entry.logical_index);
    }

    for entry in higher_efficiency_pool {
        if let Some(island) = islands.get_mut(&cpu_island_key(entry)) {
            island.shares_with_higher_efficiency = true;
        }
    }

    if islands.len() <= 1 {
        return None;
    }

    islands.values().copied().max_by_key(|island| {
        (
            !island.shares_with_higher_efficiency,
            island.max_logical_index,
            island.count,
            std::cmp::Reverse(island.key),
        )
    })
}

#[cfg(target_os = "linux")]
fn online_cpu_ids() -> Result<Vec<usize>, String> {
    let text = fs::read_to_string("/sys/devices/system/cpu/online")
        .map_err(|err| format!("read /sys/devices/system/cpu/online: {err}"))?;
    parse_cpu_list(text.trim())
}

#[cfg(target_os = "linux")]
fn parse_cpu_list(value: &str) -> Result<Vec<usize>, String> {
    let mut cpus = Vec::new();
    for part in value.split(',').filter(|part| !part.is_empty()) {
        if let Some((start, end)) = part.split_once('-') {
            let start = start
                .parse::<usize>()
                .map_err(|err| format!("invalid CPU list start {start:?}: {err}"))?;
            let end = end
                .parse::<usize>()
                .map_err(|err| format!("invalid CPU list end {end:?}: {err}"))?;
            if start > end {
                return Err(format!("invalid descending CPU range {part:?}"));
            }
            cpus.extend(start..=end);
        } else {
            cpus.push(
                part.parse::<usize>()
                    .map_err(|err| format!("invalid CPU id {part:?}: {err}"))?,
            );
        }
    }
    cpus.sort_unstable();
    cpus.dedup();
    Ok(cpus)
}

#[cfg(target_os = "linux")]
fn linux_island_index_map<'a>(islands: impl Iterator<Item = &'a str>) -> BTreeMap<String, usize> {
    let mut indexes = BTreeMap::new();
    for island in islands {
        if !indexes.contains_key(island) {
            indexes.insert(island.to_string(), indexes.len());
        }
    }
    indexes
}

#[cfg(target_os = "linux")]
fn read_linux_cpu_island_signature(cpu_path: &Path) -> Option<String> {
    read_linux_cache_island_signature(cpu_path)
}

#[cfg(target_os = "linux")]
fn read_linux_cache_island_signature(cpu_path: &Path) -> Option<String> {
    let mut best = None::<(u32, usize, String)>;
    for entry in fs::read_dir(cpu_path.join("cache")).ok()?.flatten() {
        let cache_path = entry.path();
        let Some(level) = read_u32(cache_path.join("level")) else {
            continue;
        };
        let Ok(cache_type) = fs::read_to_string(cache_path.join("type")) else {
            continue;
        };
        if cache_type.trim() != "Unified" {
            continue;
        }
        let Some(cpus) = read_cpu_list_file(cache_path.join("shared_cpu_list")) else {
            continue;
        };
        if cpus.len() <= 1 {
            continue;
        }
        let signature = format!("cache:{level}:{}", cpu_list_signature(&cpus));
        let should_replace = best
            .as_ref()
            .map(|(best_level, best_count, _)| {
                level > *best_level || (level == *best_level && cpus.len() > *best_count)
            })
            .unwrap_or(true);
        if should_replace {
            best = Some((level, cpus.len(), signature));
        }
    }
    best.map(|(_, _, signature)| signature)
}

#[cfg(target_os = "linux")]
fn read_cpu_list_file(path: impl AsRef<Path>) -> Option<Vec<usize>> {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| parse_cpu_list(text.trim()).ok())
}

#[cfg(target_os = "linux")]
fn cpu_list_signature(cpus: &[usize]) -> String {
    let mut signature = String::new();
    for (index, cpu) in cpus.iter().enumerate() {
        if index > 0 {
            signature.push(',');
        }
        signature.push_str(&cpu.to_string());
    }
    signature
}

#[cfg(target_os = "linux")]
fn read_cpu_score(cpu: usize, cpu_path: &Path) -> Option<u32> {
    // This score only separates P from non-P. LPE is not inferred from
    // frequency, CPPC, or capacity; it is split later by CPU island topology.
    read_u32(cpu_path.join("topology/core_type"))
        .or_else(|| read_cpuid_hybrid_core_type(cpu))
        .or_else(|| read_u32(cpu_path.join("cpu_capacity")))
        .or_else(|| read_u32(cpu_path.join("acpi_cppc/highest_perf")))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_cpuid_hybrid_core_type(cpu: usize) -> Option<u32> {
    let _guard = LinuxCpuAffinityGuard::pin(cpu)?;
    let vendor = std::arch::x86_64::__cpuid(0);
    if vendor.eax < 0x1a || !cpuid_vendor_is_intel(vendor.ebx, vendor.edx, vendor.ecx) {
        return None;
    }
    let cpuid = std::arch::x86_64::__cpuid_count(0x1a, 0);
    let core_type = (cpuid.eax >> 24) & 0xff;
    (core_type != 0).then_some(core_type)
}

#[cfg(all(target_os = "linux", target_arch = "x86"))]
fn read_cpuid_hybrid_core_type(cpu: usize) -> Option<u32> {
    let _guard = LinuxCpuAffinityGuard::pin(cpu)?;
    let vendor = std::arch::x86::__cpuid(0);
    if vendor.eax < 0x1a || !cpuid_vendor_is_intel(vendor.ebx, vendor.edx, vendor.ecx) {
        return None;
    }
    let cpuid = std::arch::x86::__cpuid_count(0x1a, 0);
    let core_type = (cpuid.eax >> 24) & 0xff;
    (core_type != 0).then_some(core_type)
}

#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
fn cpuid_vendor_is_intel(ebx: u32, edx: u32, ecx: u32) -> bool {
    ebx == u32::from_le_bytes(*b"Genu")
        && edx == u32::from_le_bytes(*b"ineI")
        && ecx == u32::from_le_bytes(*b"ntel")
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86", target_arch = "x86_64"))
))]
fn read_cpuid_hybrid_core_type(_cpu: usize) -> Option<u32> {
    None
}

#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
struct LinuxCpuAffinityGuard {
    original: libc::cpu_set_t,
}

#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
impl LinuxCpuAffinityGuard {
    fn pin(cpu: usize) -> Option<Self> {
        unsafe {
            let set_size = std::mem::size_of::<libc::cpu_set_t>();
            let mut original = std::mem::zeroed::<libc::cpu_set_t>();
            if libc::sched_getaffinity(0, set_size, &mut original) != 0 {
                return None;
            }

            let mut target = std::mem::zeroed::<libc::cpu_set_t>();
            libc::CPU_ZERO(&mut target);
            libc::CPU_SET(cpu, &mut target);
            if libc::sched_setaffinity(0, set_size, &target) != 0 {
                return None;
            }

            Some(Self { original })
        }
    }
}

#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
impl Drop for LinuxCpuAffinityGuard {
    fn drop(&mut self) {
        unsafe {
            let _ =
                libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &self.original);
        }
    }
}

#[cfg(target_os = "linux")]
fn efficiency_class_map(scores: impl Iterator<Item = u32>) -> BTreeMap<u32, u8> {
    let mut values = scores.collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| (value, index.min(u8::MAX as usize) as u8))
        .collect()
}

#[cfg(target_os = "linux")]
fn read_numa_node(cpu_path: &Path) -> Option<usize> {
    let entries = fs::read_dir(cpu_path).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(node) = name.strip_prefix("node")
            && let Ok(node) = node.parse::<usize>()
        {
            return Some(node);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_u32(path: impl AsRef<Path>) -> Option<u32> {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse::<u32>().ok())
}

#[cfg(target_os = "linux")]
fn read_usize(path: impl AsRef<Path>) -> Option<usize> {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse::<usize>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_cache_selection_uses_one_preferred_windows_l3_cache_relationship() {
        let caches = vec![
            L3CacheAffinity {
                group: 0,
                mask: 0x000f,
                cache_size: 32 * 1024 * 1024,
            },
            L3CacheAffinity {
                group: 0,
                mask: 0x00f0,
                cache_size: 96 * 1024 * 1024,
            },
            L3CacheAffinity {
                group: 0,
                mask: 0x0f00,
                cache_size: 128 * 1024 * 1024,
            },
            L3CacheAffinity {
                group: 0,
                mask: 0xf000,
                cache_size: 128 * 1024 * 1024,
            },
        ];

        assert_eq!(
            select_c_l3_cache_affinities(&caches),
            vec![L3CacheAffinity {
                group: 0,
                mask: 0x0f00,
                cache_size: 128 * 1024 * 1024,
            }]
        );
    }

    #[test]
    fn c_cache_selection_collapses_homogeneous_l3_topology_to_one_ccd() {
        let caches = vec![
            L3CacheAffinity {
                group: 0,
                mask: 0x00ff,
                cache_size: 128 * 1024 * 1024,
            },
            L3CacheAffinity {
                group: 0,
                mask: 0xff00,
                cache_size: 128 * 1024 * 1024,
            },
        ];

        assert_eq!(
            select_c_l3_cache_affinities(&caches),
            vec![L3CacheAffinity {
                group: 0,
                mask: 0x00ff,
                cache_size: 128 * 1024 * 1024,
            }]
        );
    }

    #[test]
    fn l3_cache_affinity_contains_only_processors_in_its_group_mask() {
        let cache = L3CacheAffinity {
            group: 1,
            mask: 0b1010,
            cache_size: 96 * 1024 * 1024,
        };

        assert!(!cache.contains(0, 1));
        assert!(cache.contains(1, 1));
        assert!(!cache.contains(1, 2));
        assert!(cache.contains(1, 3));
        assert!(!cache.contains(1, usize::BITS as usize));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_cache_island_signature_uses_highest_shared_unified_cache() {
        let cpu = LinuxTestCpuDir::new("highest-shared-unified-cache");
        write_linux_cache_index(cpu.path(), "index0", "1", "Data", "0");
        write_linux_cache_index(cpu.path(), "index1", "2", "Unified", "0-3");
        write_linux_cache_index(cpu.path(), "index2", "3", "Unified", "0-11");

        assert_eq!(
            read_linux_cpu_island_signature(cpu.path()),
            Some("cache:3:0,1,2,3,4,5,6,7,8,9,10,11".to_string())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_cache_island_signature_skips_malformed_cache_entries() {
        let cpu = LinuxTestCpuDir::new("malformed-cache-entries");
        write_linux_cache_index(cpu.path(), "index0", "broken", "Unified", "12-15");
        write_linux_cache_index(cpu.path(), "index1", "2", "Unified", "12-15");
        std::fs::remove_file(cpu.path().join("cache/index1/type")).unwrap();
        write_linux_cache_index(cpu.path(), "index2", "2", "Unified", "12-15");

        assert_eq!(
            read_linux_cpu_island_signature(cpu.path()),
            Some("cache:2:12,13,14,15".to_string())
        );
    }

    #[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
    #[test]
    fn cpuid_vendor_gate_accepts_only_intel_vendor_string() {
        assert!(cpuid_vendor_is_intel(
            u32::from_le_bytes(*b"Genu"),
            u32::from_le_bytes(*b"ineI"),
            u32::from_le_bytes(*b"ntel")
        ));
        assert!(!cpuid_vendor_is_intel(
            u32::from_le_bytes(*b"Auth"),
            u32::from_le_bytes(*b"enti"),
            u32::from_le_bytes(*b"cAMD")
        ));
    }

    #[test]
    fn x3d_processor_brand_gate_matches_9955hx3d_suffix() {
        assert!(processor_brand_contains_x3d(
            b"AMD Ryzen 9 9955HX3D 16-Core Processor"
        ));
        assert!(processor_brand_contains_x3d(
            b"AMD Ryzen 9 7950X3D 16-Core Processor"
        ));
        assert!(!processor_brand_contains_x3d(
            b"AMD Ryzen 9 9955HX 16-Core Processor"
        ));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn cpuid_display_family_decodes_extended_amd_family() {
        let eax = (0x0f << 8) | (0x0a << 20);

        assert_eq!(display_family_from_cpuid_eax(eax), 0x19);
    }

    #[cfg(target_os = "linux")]
    struct LinuxTestCpuDir {
        path: std::path::PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl LinuxTestCpuDir {
        fn new(name: &str) -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "affix-linux-topology-{name}-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for LinuxTestCpuDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[cfg(target_os = "linux")]
    fn write_linux_cache_index(
        cpu_path: &std::path::Path,
        index: &str,
        level: &str,
        cache_type: &str,
        shared_cpu_list: &str,
    ) {
        let index_path = cpu_path.join("cache").join(index);
        std::fs::create_dir_all(&index_path).unwrap();
        std::fs::write(index_path.join("level"), level).unwrap();
        std::fs::write(index_path.join("type"), cache_type).unwrap();
        std::fs::write(index_path.join("shared_cpu_list"), shared_cpu_list).unwrap();
    }
}
