use tracing::warn;

use crate::service::ServiceError;
use crate::topology::{
    CpuSetEntry, CpuTopology, choose_efficiency_island, cpu_island_key, efficiency_classes,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AffinityPolicy {
    Mask(usize),
    Expression(AffinityExpression),
}

impl AffinityPolicy {
    pub fn mask(&self) -> Result<Option<usize>, ServiceError> {
        match self {
            Self::Mask(mask) => Ok(Some(*mask)),
            Self::Expression(expression) => expression.mask(),
        }
    }

    pub fn log_value(&self) -> String {
        match self {
            Self::Mask(mask) => format!("0x{mask:x}"),
            Self::Expression(expression) => expression.source.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffinityExpression {
    pub source: String,
    pub terms: Vec<AffinityTerm>,
}

impl AffinityExpression {
    pub fn parse(source: String) -> Result<Self, String> {
        let trimmed = source.trim();
        if trimmed.is_empty() {
            return Err("affinity expression must not be empty".to_string());
        }

        let mut terms = Vec::new();
        for raw_term in trimmed.split('+') {
            let term = raw_term.trim();
            if term.is_empty() {
                return Err(format!("empty affinity term in {trimmed:?}"));
            }

            let parsed = match term.to_ascii_uppercase().as_str() {
                "P" => AffinityTerm::Performance,
                "E" => AffinityTerm::Efficiency,
                "LPE" | "LP-E" => AffinityTerm::LowPowerEfficiency,
                "C" | "X3D" => AffinityTerm::Cache,
                _ => {
                    let index = term.parse::<usize>().map_err(|err| {
                        format!("unsupported affinity term {term:?}; expected P, E, LPE, C, or a 0-based logical processor index: {err}")
                    })?;
                    AffinityTerm::LogicalIndex(index)
                }
            };
            terms.push(parsed);
        }

        Ok(Self {
            source: trimmed.to_string(),
            terms,
        })
    }

    pub fn mask(&self) -> Result<Option<usize>, ServiceError> {
        let topology =
            CpuTopology::read_or_fallback().map_err(|message| ServiceError::Affinity {
                expression: self.source.clone(),
                message,
            })?;
        let mask = self
            .mask_from_entries(&topology.entries)
            .map_err(|message| ServiceError::Affinity {
                expression: self.source.clone(),
                message,
            })?;
        Ok(mask)
    }

    pub fn mask_from_entries(&self, entries: &[CpuSetEntry]) -> Result<Option<usize>, String> {
        if entries.is_empty() {
            return Err("CPU topology is empty".to_string());
        }

        let candidates: Vec<&CpuSetEntry> = entries
            .iter()
            .filter(|entry| entry.group == 0 && !entry.allocated_to_other && !entry.realtime)
            .collect();
        if candidates.is_empty() {
            return Err("no usable group-0 CPU-set entries are available".to_string());
        }
        let homogeneous = efficiency_classes(&candidates).len() == 1;
        let tiers = AffinityTiers::classify(&candidates)?;

        let mut mask = 0usize;
        match self.terms.as_slice() {
            [AffinityTerm::Efficiency] if homogeneous => {
                let entries = homogeneous_efficiency_entries(&candidates);
                add_entries_to_mask(&mut mask, &entries)?;
            }
            [AffinityTerm::LowPowerEfficiency] if homogeneous => {
                let entries = homogeneous_low_power_efficiency_entries(&candidates);
                add_entries_to_mask(&mut mask, &entries)?;
            }
            terms if homogeneous && is_homogeneous_efficiency_plus_lpe(terms) => {
                let entries = homogeneous_efficiency_entries(&candidates);
                add_entries_to_mask(&mut mask, &entries)?;
            }
            _ => {}
        }

        for term in &self.terms {
            match *term {
                AffinityTerm::LogicalIndex(index) => {
                    add_filtered_logical_index_to_mask(&mut mask, &candidates, index);
                }
                AffinityTerm::Performance => {
                    add_entries_to_mask(&mut mask, &tiers.performance)?;
                }
                AffinityTerm::Efficiency => {
                    add_entries_to_mask(&mut mask, &tiers.efficiency)?;
                }
                AffinityTerm::LowPowerEfficiency => {
                    add_entries_to_mask(&mut mask, &tiers.low_power_efficiency)?;
                }
                AffinityTerm::Cache => {
                    add_entries_to_mask(&mut mask, &tiers.cache)?;
                }
            }
        }

        if mask == 0 { Ok(None) } else { Ok(Some(mask)) }
    }
}

pub fn is_homogeneous_efficiency_plus_lpe(terms: &[AffinityTerm]) -> bool {
    terms.len() == 2
        && terms.contains(&AffinityTerm::Efficiency)
        && terms.contains(&AffinityTerm::LowPowerEfficiency)
}

pub fn homogeneous_efficiency_entries<'a>(candidates: &[&'a CpuSetEntry]) -> Vec<&'a CpuSetEntry> {
    candidates
        .iter()
        .copied()
        .filter(|entry| entry.logical_index % 2 == 1)
        .collect()
}

pub fn homogeneous_low_power_efficiency_entries<'a>(
    candidates: &[&'a CpuSetEntry],
) -> Vec<&'a CpuSetEntry> {
    let mut entries = candidates.to_vec();
    entries.sort_by_key(|entry| entry.logical_index);

    match entries.len() {
        0 => Vec::new(),
        1 | 2 => entries,
        3..=7 => entries[entries.len() - 2..].to_vec(),
        8 => entries[entries.len() - 4..].to_vec(),
        _ => {
            let mut selected = Vec::new();
            let mut logical_index = entries[entries.len() - 1].logical_index;
            for _ in 0..4 {
                if let Some(entry) = entries
                    .iter()
                    .find(|entry| entry.logical_index == logical_index)
                    .copied()
                {
                    selected.push(entry);
                }
                let Some(next_index) = logical_index.checked_sub(2) else {
                    break;
                };
                logical_index = next_index;
            }
            selected
        }
    }
}

pub fn add_entries_to_mask(mask: &mut usize, entries: &[&CpuSetEntry]) -> Result<(), String> {
    for entry in entries {
        add_logical_index_to_mask(mask, entry.logical_index)?;
    }
    Ok(())
}

pub fn add_filtered_logical_index_to_mask(
    mask: &mut usize,
    candidates: &[&CpuSetEntry],
    index: usize,
) {
    let Some(entry) = candidates
        .iter()
        .find(|entry| entry.logical_index == index)
        .copied()
    else {
        warn!(
            logical_index = index,
            "affinity expression ignored unavailable logical processor index"
        );
        return;
    };
    if let Err(message) = add_logical_index_to_mask(mask, entry.logical_index) {
        warn!(
            logical_index = index,
            reason = %message,
            "affinity expression ignored unusable logical processor index"
        );
    }
}

pub fn add_logical_index_to_mask(mask: &mut usize, index: usize) -> Result<(), String> {
    if index >= usize::BITS as usize {
        return Err(format!(
            "logical processor index {index} cannot fit in process affinity mask"
        ));
    }
    *mask |= 1usize << index;
    Ok(())
}

pub struct AffinityTiers<'a> {
    pub performance: Vec<&'a CpuSetEntry>,
    pub efficiency: Vec<&'a CpuSetEntry>,
    pub low_power_efficiency: Vec<&'a CpuSetEntry>,
    pub cache: Vec<&'a CpuSetEntry>,
}

impl<'a> AffinityTiers<'a> {
    pub fn classify(candidates: &[&'a CpuSetEntry]) -> Result<Self, String> {
        let cache = candidates
            .iter()
            .copied()
            .filter(|entry| entry.cache)
            .collect::<Vec<_>>();
        let classes = efficiency_classes(candidates);
        let Some(&max_class) = classes.last() else {
            return Err("CPU topology has no efficiency classes".to_string());
        };

        if classes.len() == 1 {
            return Ok(Self {
                performance: Vec::new(),
                efficiency: Vec::new(),
                low_power_efficiency: Vec::new(),
                cache,
            });
        }

        let performance = candidates
            .iter()
            .copied()
            .filter(|entry| entry.efficiency_class == max_class)
            .collect::<Vec<_>>();

        let Some(&min_class) = classes.first() else {
            return Err("CPU topology has no efficiency classes".to_string());
        };

        if classes.len() >= 3 {
            let efficiency = candidates
                .iter()
                .copied()
                .filter(|entry| {
                    entry.efficiency_class != min_class && entry.efficiency_class != max_class
                })
                .collect();
            let low_power_efficiency = candidates
                .iter()
                .copied()
                .filter(|entry| entry.efficiency_class == min_class)
                .collect();
            return Ok(Self {
                performance,
                efficiency,
                low_power_efficiency,
                cache,
            });
        }

        let non_performance = candidates
            .iter()
            .copied()
            .filter(|entry| entry.efficiency_class == min_class)
            .collect::<Vec<_>>();
        let higher_efficiency = candidates
            .iter()
            .copied()
            .filter(|entry| entry.efficiency_class > min_class)
            .collect::<Vec<_>>();

        let Some(island) = choose_efficiency_island(&non_performance, &higher_efficiency) else {
            return Ok(Self {
                performance,
                efficiency: non_performance.clone(),
                low_power_efficiency: non_performance,
                cache,
            });
        };

        let low_power_efficiency = non_performance
            .iter()
            .copied()
            .filter(|entry| cpu_island_key(entry) == island.key)
            .collect::<Vec<_>>();
        let efficiency = non_performance
            .iter()
            .copied()
            .filter(|entry| cpu_island_key(entry) != island.key)
            .collect::<Vec<_>>();

        if efficiency.is_empty() || low_power_efficiency.is_empty() {
            Ok(Self {
                performance,
                efficiency: non_performance.clone(),
                low_power_efficiency: non_performance,
                cache,
            })
        } else {
            Ok(Self {
                performance,
                efficiency,
                low_power_efficiency,
                cache,
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AffinityTerm {
    LogicalIndex(usize),
    Performance,
    Efficiency,
    LowPowerEfficiency,
    Cache,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn affinity_expression_uses_zero_based_logical_processor_numbers() {
        let expression = AffinityExpression::parse("0+1+3".to_string()).unwrap();
        let entries = (0..4).map(|index| cpu_set(index, 0)).collect::<Vec<_>>();

        assert_eq!(
            expression.mask_from_entries(&entries).unwrap(),
            Some(0b1011)
        );
    }

    #[test]
    fn affinity_expression_skips_numeric_terms_outside_usable_cpu_sets() {
        let expression = AffinityExpression::parse("0+1+9".to_string()).unwrap();
        let entries = (0..4).map(|index| cpu_set(index, 0)).collect::<Vec<_>>();

        assert_eq!(
            expression.mask_from_entries(&entries).unwrap(),
            Some(0b0011)
        );
    }

    #[test]
    fn affinity_expression_returns_none_for_empty_numeric_result() {
        let expression = AffinityExpression::parse("2".to_string()).unwrap();
        let mut entries = (0..4).map(|index| cpu_set(index, 0)).collect::<Vec<_>>();
        entries[2].allocated_to_other = true;

        assert_eq!(expression.mask_from_entries(&entries).unwrap(), None);

        let unavailable = AffinityExpression::parse("9+10".to_string()).unwrap();
        assert_eq!(unavailable.mask_from_entries(&entries).unwrap(), None);
    }

    #[test]
    fn numeric_terms_resolve_os_logical_indices_and_union_with_portable_terms() {
        let entries = vec![cpu_set(0, 2), cpu_set(2, 0), cpu_set(4, 0)];

        assert_eq!(
            AffinityExpression::parse("P+2".to_string())
                .unwrap()
                .mask_from_entries(&entries)
                .unwrap(),
            Some((1usize << 0) | (1usize << 2))
        );
        assert_eq!(
            AffinityExpression::parse("0+2".to_string())
                .unwrap()
                .mask_from_entries(&entries)
                .unwrap(),
            Some((1usize << 0) | (1usize << 2))
        );
        assert_eq!(
            AffinityExpression::parse("P+0".to_string())
                .unwrap()
                .mask_from_entries(&entries)
                .unwrap(),
            Some(1usize << 0)
        );
    }

    #[test]
    fn numeric_term_zero_is_accepted_as_first_logical_core() {
        let expression = AffinityExpression::parse("0".to_string()).unwrap();
        let entries = vec![cpu_set(0, 0)];
        assert_eq!(expression.mask_from_entries(&entries).unwrap(), Some(1));
    }

    #[test]
    fn heterogeneous_affinity_expression_splits_p_e_and_lpe_tiers() {
        let expression = AffinityExpression::parse("E+LPE".to_string()).unwrap();
        let entries = vec![cpu_set(0, 2), cpu_set(4, 1), cpu_set(8, 0)];

        assert_eq!(
            expression.mask_from_entries(&entries).unwrap(),
            Some((1usize << 4) | (1usize << 8))
        );
    }

    #[test]
    fn two_tier_lpe_falls_back_to_e_tier() {
        let expression = AffinityExpression::parse("LPE".to_string()).unwrap();
        let entries = vec![cpu_set(0, 1), cpu_set(1, 1), cpu_set(4, 0), cpu_set(5, 0)];

        assert_eq!(
            expression.mask_from_entries(&entries).unwrap(),
            Some((1usize << 4) | (1usize << 5))
        );
    }

    #[test]
    fn two_tier_lpe_uses_distinct_low_power_island_when_present() {
        let e = AffinityExpression::parse("E".to_string()).unwrap();
        let lpe = AffinityExpression::parse("LPE".to_string()).unwrap();
        let e_plus_lpe = AffinityExpression::parse("E+LPE".to_string()).unwrap();
        let entries = vec![
            cpu_set_with_island(0, 1, 0),
            cpu_set_with_island(1, 1, 0),
            cpu_set_with_island(4, 0, 1),
            cpu_set_with_island(5, 0, 1),
            cpu_set_with_island(8, 0, 2),
            cpu_set_with_island(9, 0, 2),
        ];

        assert_eq!(
            e.mask_from_entries(&entries).unwrap(),
            Some((1usize << 4) | (1usize << 5))
        );
        assert_eq!(
            lpe.mask_from_entries(&entries).unwrap(),
            Some((1usize << 8) | (1usize << 9))
        );
        assert_eq!(
            e_plus_lpe.mask_from_entries(&entries).unwrap(),
            Some((1usize << 4) | (1usize << 5) | (1usize << 8) | (1usize << 9))
        );
    }

    #[test]
    fn homogeneous_only_sole_e_and_lpe_use_deterministic_lower_tier_fallbacks() {
        let entries = (0..6).map(|index| cpu_set(index, 0)).collect::<Vec<_>>();
        let e = AffinityExpression::parse("E".to_string()).unwrap();
        let e_plus_lpe = AffinityExpression::parse("E+LPE".to_string()).unwrap();
        let lpe = AffinityExpression::parse("LPE".to_string()).unwrap();
        let p = AffinityExpression::parse("P".to_string()).unwrap();
        let p_plus_lpe = AffinityExpression::parse("P+LPE".to_string()).unwrap();
        let p_plus_e_plus_lpe = AffinityExpression::parse("P+E+LPE".to_string()).unwrap();
        let x3d = AffinityExpression::parse("C".to_string()).unwrap();

        assert_eq!(e.mask_from_entries(&entries).unwrap(), Some(0b10_1010));
        assert_eq!(lpe.mask_from_entries(&entries).unwrap(), Some(0b11_0000));
        assert_eq!(
            e_plus_lpe.mask_from_entries(&entries).unwrap(),
            e.mask_from_entries(&entries).unwrap()
        );
        assert_eq!(p.mask_from_entries(&entries).unwrap(), None);
        assert_eq!(p_plus_lpe.mask_from_entries(&entries).unwrap(), None);
        assert_eq!(p_plus_e_plus_lpe.mask_from_entries(&entries).unwrap(), None);
        assert_eq!(x3d.mask_from_entries(&entries).unwrap(), None);
    }

    #[test]
    fn homogeneous_lpe_is_core_count_aware() {
        let lpe = AffinityExpression::parse("LPE".to_string()).unwrap();

        let four = (0..4).map(|index| cpu_set(index, 0)).collect::<Vec<_>>();
        assert_eq!(lpe.mask_from_entries(&four).unwrap(), Some(0b1100));

        let seven = (0..7).map(|index| cpu_set(index, 0)).collect::<Vec<_>>();
        assert_eq!(lpe.mask_from_entries(&seven).unwrap(), Some(0b110_0000));

        let eight = (0..8).map(|index| cpu_set(index, 0)).collect::<Vec<_>>();
        assert_eq!(lpe.mask_from_entries(&eight).unwrap(), Some(0b1111_0000));

        let twelve = (0..12).map(|index| cpu_set(index, 0)).collect::<Vec<_>>();
        assert_eq!(
            lpe.mask_from_entries(&twelve).unwrap(),
            Some((1usize << 5) | (1usize << 7) | (1usize << 9) | (1usize << 11))
        );

        let non_contiguous = [0usize, 1, 2, 3, 4, 5, 7, 8, 9]
            .into_iter()
            .map(|index| cpu_set(index, 0))
            .collect::<Vec<_>>();
        assert_eq!(
            lpe.mask_from_entries(&non_contiguous).unwrap(),
            Some((1usize << 3) | (1usize << 5) | (1usize << 7) | (1usize << 9))
        );
    }

    #[test]
    fn homogeneous_e_uses_every_second_logical_core() {
        let e = AffinityExpression::parse("E".to_string()).unwrap();
        let e_plus_lpe = AffinityExpression::parse("LPE+E".to_string()).unwrap();
        let entries = (0..10).map(|index| cpu_set(index, 0)).collect::<Vec<_>>();

        let expected =
            Some((1usize << 1) | (1usize << 3) | (1usize << 5) | (1usize << 7) | (1usize << 9));
        assert_eq!(e.mask_from_entries(&entries).unwrap(), expected);
        assert_eq!(e_plus_lpe.mask_from_entries(&entries).unwrap(), expected);
    }

    #[test]
    fn c_expression_uses_only_runtime_identified_c_cache_entries() {
        let expression = AffinityExpression::parse("C".to_string()).unwrap();
        let mut entries = (0..8).map(|index| cpu_set(index, 0)).collect::<Vec<_>>();
        for entry in entries.iter_mut().filter(|entry| entry.logical_index >= 4) {
            entry.cache = true;
            entry.last_level_cache_index = 1;
        }

        assert_eq!(
            expression.mask_from_entries(&entries).unwrap(),
            Some(0b1111_0000)
        );
    }

    fn cpu_set(logical_index: usize, efficiency_class: u8) -> CpuSetEntry {
        cpu_set_with_island(logical_index, efficiency_class, 0)
    }

    fn cpu_set_with_island(
        logical_index: usize,
        efficiency_class: u8,
        last_level_cache_index: usize,
    ) -> CpuSetEntry {
        CpuSetEntry {
            id: logical_index as u32,
            group: 0,
            logical_index,
            core_index: logical_index,
            last_level_cache_index,
            numa_node: 0,
            efficiency_class,
            cache: false,
            parked: false,
            allocated_to_other: false,
            realtime: false,
        }
    }
}
