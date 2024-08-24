use std::path::{Path, PathBuf};
use std::process;
use std::{
    env, fs,
    io::{self, Read, Write},
};

#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;

use crate::{redoxer_dir, target};

pub fn progress_bar(total_len: usize, message: String) -> indicatif::ProgressBar {
    let mut pb = indicatif::ProgressBar::new(total_len as u64);

    pb.set_style(
        indicatif::ProgressStyle::with_template(
            "{spinner:.green.bold} {msg:.cyan.bold} -> Est. [{eta_precise:.cyan}] @ [{bytes_per_sec:.cyan}]
        -> [{elapsed_precise:.green}] [{wide_bar:.cyan/blue}] [{bytes:.green}/{total_bytes:.green}]    "
        )
            .unwrap()
            .with_key("eta", |state: &indicatif::ProgressState, w: &mut dyn std::fmt::Write| {
                write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
            })
            .progress_chars("#>-")
    );

    pb = pb.with_finish(indicatif::ProgressFinish::AndLeave);
    pb.set_message(message.clone());
    pb
}

fn client_get_recurse(url: &str) -> ureq::Response {
    let response = ureq::get(url).call();
    match response {
        Ok(response) => response,
        Err(err) => {
            eprintln!("Failed to get {} with error: {}", url, err);
            std::thread::sleep(std::time::Duration::from_secs(3));
            client_get_recurse(url)
        }
    }
}

pub fn get_with_progress(
    url: impl AsRef<str> + std::marker::Send,
    progress_bar: &indicatif::ProgressBar,
) -> Vec<u8> {
    let response = client_get_recurse(url.as_ref());
    let response_length: u64 = response
        .header("Content-Length")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    progress_bar.set_length(response_length);
    let mut resp_buf = Vec::with_capacity(response_length as usize);
    match progress_bar
        .wrap_read(response.into_reader())
        .take(response_length)
        .read_to_end(&mut resp_buf)
    {
        Ok(_) => resp_buf,
        Err(_) => {
            eprintln!("Failed to complete request. Retrying...");
            std::thread::sleep(std::time::Duration::from_secs(3));
            get_with_progress(url, progress_bar)
        }
    }
}

const B: usize = 1;
const KB: usize = 1024 * B;
const MB: usize = 1024 * KB;

//Adjusted based on Content-Length header
const ROUGH_TOOLCHAIN_ARCHIVE_SIZE: usize = 300 * MB;

fn unpack_tar_with_progress<P: AsRef<Path>>(tar_bytes: &[u8], path: P) -> io::Result<()> {
    let tar_progress_bar = progress_bar(
        tar_bytes.len(),
        "Extracting toolchain archive...".to_string(),
    );

    let out_path = path.as_ref();

    let mut archive = tar::Archive::new(tar_progress_bar.wrap_read(tar_bytes));
    let mut entries = archive.entries().unwrap();
    while let Some(Ok(mut entry)) = entries.next() {
        let entry_path = out_path.join(entry.path()?);

        let entry_type = entry.header().entry_type();

        if entry_type != tar::EntryType::Directory {
            let _possibly_exists = fs::create_dir_all(entry_path.parent().unwrap());
        }

        match entry_type {
            tar::EntryType::Directory => {
                let _possibly_exists = fs::create_dir_all(entry_path);
                tar_progress_bar.inc(entry.size());
            }
            tar::EntryType::Regular => {
                let mut entry_file = fs::File::create(entry_path).unwrap_or_else(|err| {
                    panic!("Failed to create file! Error: {:?}", err);
                });

                let mut read_buf = [0; 1024];
                let mut entry_writer = tar_progress_bar.wrap_write(&mut entry_file);

                while let Ok(read_bytes) = entry.read(&mut read_buf) {
                    if read_bytes == 0 {
                        break;
                    }
                    entry_writer
                        .write_all(&read_buf[..read_bytes])
                        .unwrap_or_else(|err| {
                            panic!("Failed to write to file! Error: {:?}", err);
                        });
                }

                let mtime: std::time::SystemTime = if let Ok(mtime) = entry.header().mtime() {
                    std::time::UNIX_EPOCH
                        .checked_add(std::time::Duration::from_secs(mtime))
                        .unwrap_or(std::time::SystemTime::now())
                } else {
                    std::time::SystemTime::now()
                };
                entry_file
                    .set_times(
                        fs::FileTimes::new()
                            .set_accessed(std::time::SystemTime::now())
                            .set_modified(mtime),
                    )
                    .unwrap_or_else(|err| {
                        panic!("Failed to set file times! Error: {:?}", err);
                    });

                #[cfg(not(target_family = "unix"))]
                if entry.header().mode().unwrap_or(111) == 000 {
                    entry_file.set_readonly(true);
                }

                #[cfg(target_family = "unix")]
                entry_file
                    .set_permissions(fs::Permissions::from_mode(
                        entry.header().mode().unwrap_or(0o644),
                    ))
                    .unwrap_or_else(|err| {
                        panic!("Failed to set file permissions! Error: {:?}", err);
                    });
            }
            _ => {
                // Other types of entries do not need custom handling, and use negligible storage
                entry.unpack(entry_path).unwrap_or_else(|err| {
                    panic!("Failed to unpack entry! Error: {:?}", err);
                });
                tar_progress_bar.inc(entry.size());
            }
        }
    }

    tar_progress_bar.finish();
    Ok(())
}
fn download_extract_toolchain<P: AsRef<Path>>(url: &str, path: P) -> io::Result<()> {
    let download_progress_bar = progress_bar(
        ROUGH_TOOLCHAIN_ARCHIVE_SIZE,
        "Downloading toolchain...".to_string(),
    );
    let tar_gz_bytes = get_with_progress(url, &download_progress_bar);

    download_progress_bar.finish();

    let gz_decoder_progress_bar = progress_bar(
        tar_gz_bytes.len(),
        "Decompressing toolchain archive...".to_string(),
    );
    let mut tar_bytes = Vec::new();

    {
        let tar_bytes_writer = flate2::write::GzDecoder::new(&mut tar_bytes);
        let mut tar_bytes_writer_with_progress =
            gz_decoder_progress_bar.wrap_write(tar_bytes_writer);
        tar_bytes_writer_with_progress.write_all(&tar_gz_bytes)?;
        gz_decoder_progress_bar.finish();
    }
    unpack_tar_with_progress(tar_bytes.as_slice(), path)
}

pub fn toolchain() -> io::Result<PathBuf> {
    if let Ok(redoxer_toolchain) = env::var("REDOXER_TOOLCHAIN") {
        return Ok(PathBuf::from(redoxer_toolchain));
    }

    let target_str = target();
    let url = format!(
        "https://static.redox-os.org/toolchain/{}/rust-install.tar.gz",
        target_str
    );
    let toolchain_dir = redoxer_dir().join("toolchain");
    if !toolchain_dir.is_dir()
        || !toolchain_dir.join(target_str).is_dir()
        || !toolchain_dir
            .join("bin")
            .join(format!("{}-gcc", target_str))
            .is_file()
    {
        download_extract_toolchain(url.as_str(), &toolchain_dir)?;
    }

    Ok(toolchain_dir)
}

pub fn main(_args: &[String]) {
    match toolchain() {
        Ok(_) => {
            process::exit(0);
        }
        Err(err) => {
            panic!("redoxer toolchain: {:?}", err);
        }
    }
}
