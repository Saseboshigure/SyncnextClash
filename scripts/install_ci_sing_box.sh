#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <install-directory>" >&2
  exit 2
fi

version="1.13.15"
archive_name="sing-box-${version}-linux-amd64.tar.gz"
archive_sha256="a3a3ff223b23c3f4731d0a17cb0ef94c97ce257c70721a5b07dc7ca079203c9f"
install_dir="$1"
download_dir="${RUNNER_TEMP:?RUNNER_TEMP is required}/syncnext-sing-box-${version}"
archive_path="${download_dir}/${archive_name}"
extracted_path="${download_dir}/sing-box-${version}-linux-amd64/sing-box"

mkdir -p "${download_dir}" "${install_dir}"
curl -fsSL \
  "https://github.com/SagerNet/sing-box/releases/download/v${version}/${archive_name}" \
  -o "${archive_path}"
printf '%s  %s\n' "${archive_sha256}" "${archive_path}" | sha256sum --check --status
tar -xzf "${archive_path}" -C "${download_dir}"
install -m 0755 "${extracted_path}" "${install_dir}/sing-box"
"${install_dir}/sing-box" version
