//! Archive utilities for multi-file uploads

use std::io::{Read, Seek, Write};
use std::path::Path;
use zip::write::FileOptions;
use zip::CompressionMethod;

/// Creates a ZIP archive from multiple files/directories
pub fn create_zip_archive(paths: &[String], _archive_name: &str) -> Result<Vec<u8>, String> {
    let mut buffer = std::io::Cursor::new(Vec::new());

    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options = FileOptions::<()>::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o644);

        for path_str in paths {
            let path = Path::new(path_str);
            if path.is_file() {
                add_file_to_zip(
                    &mut zip,
                    path,
                    path.file_name().unwrap().to_str().unwrap(),
                    &options,
                )?;
            } else if path.is_dir() {
                add_directory_to_zip(&mut zip, path, "", &options)?;
            }
        }

        zip.finish()
            .map_err(|e| format!("Failed to finish ZIP: {}", e))?;
    }

    Ok(buffer.into_inner())
}

fn add_file_to_zip<W: Write + Seek>(
    zip: &mut zip::ZipWriter<W>,
    file_path: &Path,
    name_in_archive: &str,
    options: &FileOptions<()>,
) -> Result<(), String> {
    let mut file = std::fs::File::open(file_path)
        .map_err(|e| format!("Failed to open file {:?}: {}", file_path, e))?;

    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .map_err(|e| format!("Failed to read file {:?}: {}", file_path, e))?;

    zip.start_file(name_in_archive, *options)
        .map_err(|e| format!("Failed to start file in ZIP: {}", e))?;

    zip.write_all(&contents)
        .map_err(|e| format!("Failed to write to ZIP: {}", e))?;

    Ok(())
}

fn add_directory_to_zip<W: Write + Seek>(
    zip: &mut zip::ZipWriter<W>,
    dir_path: &Path,
    prefix: &str,
    options: &FileOptions<()>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir_path)
        .map_err(|e| format!("Failed to read directory {:?}: {}", dir_path, e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_str().unwrap_or("unknown");

        let archive_path = if prefix.is_empty() {
            name_str.to_string()
        } else {
            format!("{}/{}", prefix, name_str)
        };

        if path.is_file() {
            add_file_to_zip(zip, &path, &archive_path, options)?;
        } else if path.is_dir() {
            // Add directory entry
            zip.add_directory(&archive_path, *options)
                .map_err(|e| format!("Failed to add directory to ZIP: {}", e))?;
            add_directory_to_zip(zip, &path, &archive_path, options)?;
        }
    }

    Ok(())
}

/// Checks if any path is a directory or if there are multiple paths
pub fn needs_archiving(paths: &[String]) -> bool {
    if paths.len() > 1 {
        return true;
    }
    if let Some(path) = paths.first() {
        return Path::new(path).is_dir();
    }
    false
}

/// Generates archive name from paths
pub fn generate_archive_name(paths: &[String]) -> String {
    if paths.len() == 1 {
        let path = Path::new(&paths[0]);
        if path.is_dir() {
            return format!(
                "{}.zip",
                path.file_name().unwrap().to_str().unwrap_or("archive")
            );
        }
    }

    // Multiple files - use first file name or "archive"
    if let Some(first) = paths.first() {
        let path = Path::new(first);
        if let Some(stem) = path.file_stem() {
            return format!(
                "{}_and_{}_more.zip",
                stem.to_str().unwrap_or("files"),
                paths.len() - 1
            );
        }
    }

    "archive.zip".to_string()
}
