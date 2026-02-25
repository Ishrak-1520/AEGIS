import os
import json
import time
import urllib.request

def download_vulnerable_code():
    base_dir = "./datasets/ossf-cve-benchmark"
    cves_dir = os.path.join(base_dir, "CVEs")
    target_dir = os.path.join(base_dir, "src_downloaded")

    if not os.path.exists(cves_dir):
        print(f"Error: Could not find {cves_dir}.")
        return

    print(f"Creating storage directory at: {target_dir}")
    os.makedirs(target_dir, exist_ok=True)
    
    # Smarter helper to find keys recursively, regardless of schema changes
    def find_key(obj, keys_to_find):
        if isinstance(obj, dict):
            for k in keys_to_find:
                if k in obj: return obj[k]
            for v in obj.values():
                res = find_key(v, keys_to_find)
                if res is not None: return res
        elif isinstance(obj, list):
            for item in obj:
                res = find_key(item, keys_to_find)
                if res is not None: return res
        return None

    # Helper to find all file paths
    def extract_files(obj):
        files = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                # Checking all common keys for file paths
                if k in ["file", "path", "filename", "filePath"] and isinstance(v, str):
                    files.add(v)
                else:
                    files.update(extract_files(v))
        elif isinstance(obj, list):
            for item in obj:
                files.update(extract_files(item))
        return files

    count = 0
    missing_data_count = 0

    for filename in os.listdir(cves_dir):
        if not filename.endswith(".json"): continue
        
        cve_id = filename.replace(".json", "")
        json_path = os.path.join(cves_dir, filename)
        
        with open(json_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except Exception:
                continue
                
        # Look for the data using an array of possible key names!
        repo_url = find_key(data, ["repository", "repo_url", "repo"])
        commit = find_key(data, ["vulnerable", "vulnerableCommit", "commit", "vulnerable_commit", "vulnerable_hash"])
        files_to_download = extract_files(data)
        
        if not repo_url or not commit or not files_to_download:
            # This will tell us exactly what data is missing from the JSON
            print(f"Skipping {cve_id} - Missing JSON Data: (Found Repo: {bool(repo_url)}, Found Commit: {bool(commit)}, Found Files: {len(files_to_download)})")
            missing_data_count += 1
            continue
            
        repo_url = str(repo_url).replace(".git", "")
        raw_base = repo_url.replace("https://github.com", "https://raw.githubusercontent.com")
        
        for file_path in files_to_download:
            download_url = f"{raw_base}/{commit}/{file_path}"
            
            local_folder = os.path.join(target_dir, cve_id)
            os.makedirs(local_folder, exist_ok=True)
            local_file = os.path.join(local_folder, os.path.basename(file_path))
            
            if os.path.exists(local_file):
                count += 1
                continue
                
            try:
                print(f"Fetching {cve_id} -> {os.path.basename(file_path)}...")
                # Add a User-Agent to prevent GitHub from blocking the download!
                req = urllib.request.Request(download_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
                with urllib.request.urlopen(req) as response, open(local_file, 'wb') as out_file:
                    out_file.write(response.read())
                count += 1
                time.sleep(0.3) # Avoid GitHub rate limiting
            except Exception as e:
                print(f"Failed to fetch {cve_id}: {e}")

    print(f"\n✅ Success! Downloaded {count} vulnerable source code files.")
    if missing_data_count > 0:
        print(f"⚠️ Skipped {missing_data_count} files due to missing metadata in the JSON.")

if __name__ == "__main__":
    download_vulnerable_code()