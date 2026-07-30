use tracing::debug;

pub fn calculate_text_embedding(image_name: &crate::storage::ImageName) -> Option<Vec<f32>> {
    debug!(
        image = %image_name,
        "text embedding metric disabled because the orthos path dependency is unavailable"
    );
    None
}
