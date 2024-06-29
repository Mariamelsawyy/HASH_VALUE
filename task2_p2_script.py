import os
import zipfile
import rarfile
import hashlib


rarfile.UNRAR_TOOL = r'C:\Program Files\WinRAR\UnRAR.exe'

def hash_file(filename):
    hash_alg = {
        'md5': hashlib.md5(),
        'sha512': hashlib.sha512(),
        'sha256': hashlib.sha256(),
        'sha384': hashlib.sha384()
    }

    with open(filename, 'rb') as f:
        file = f.read()
        for algorithm in hash_alg.values():
            algorithm.update(file)

    return {name: algorithm.hexdigest() for name, algorithm in hash_alg.items()}

def hashing(filename):
    # to get the hash value for every single file in the folder
    file_hashes = {
        'md5': [],
        'sha512': [],
        'sha256': [],
        'sha384': []
    }
    for root, dirs, files in os.walk(filename):
        for file in files:
            if not file.lower().endswith(('.zip', '.rar')):
                file_path = os.path.join(root, file)
                hashes = hash_file(file_path)

                for algorithm in file_hashes:
                    file_hashes[algorithm].append((file_path, hashes[algorithm]))

    return file_hashes

def extract_zip(zip_path, extract_to):
    if not os.path.exists(extract_to):
        os.makedirs(extract_to)
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)

def extract_rar(rar_path, extract_to):
    if not os.path.exists(extract_to):
        os.makedirs(extract_to)
    rar_files = []
    with rarfile.RarFile(rar_path, 'r') as rar_ref:
        for file in rar_ref.infolist():
            rar_ref.extract(file, extract_to)
            rar_files.append(os.path.join(extract_to, file.filename))
    return rar_files

def unzipping(zip_path, content_path):
    list_file = []

    def _unzipping(zip_path, content_path):
        if not os.path.exists(content_path):
            os.makedirs(content_path)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            list_files = zip_ref.namelist()
            for file_name in list_files:
                extracted_path = os.path.join(content_path, file_name)
                try:
                    zip_ref.extract(file_name, content_path)
                except PermissionError:
                    continue
                if os.path.isdir(extracted_path):
                    continue
                if zipfile.is_zipfile(extracted_path):
                    nested_content_path = os.path.join(content_path, os.path.splitext(file_name)[0])
                    _unzipping(extracted_path, nested_content_path)
                elif extracted_path.lower().endswith('.rar'):
                    nested_content_path = os.path.join(content_path, os.path.splitext(file_name)[0])
                    rar_files = extract_rar(extracted_path, nested_content_path)
                    list_file.extend(rar_files if rar_files else [extracted_path])
                else:
                    list_file.append(extracted_path)

    _unzipping(zip_path, content_path)
    return list_file

if __name__ == '__main__':
    current_dir = os.getcwd()
    zip_file = r'Task2.zip'
    zip_path = os.path.join(current_dir,zip_file) # Path to the main zip file

    content_path = os.path.join(current_dir,'zipping') # Path where contents will be extracted

    list_file = unzipping(zip_path, content_path)
    file_hashes = hashing(content_path)

    list2 = [
        'f11fa868ac3dee1e5fbd985fe15ba6d34c7ec0abb47babe0d34a35514c49c86a',
        '6b2f645881bed988d32c4f7241f3a8dd',
        '69d55495b7d59d72d32a07755a39197617927248edc3b72fb476f3ff3d05bd33c967928acf05df93897aedd58c75064694e6bc7a9b0a6aa618a5987ffadfed2c',
        '9fd20defd9b97add19d682d83e1a8ed5f20496c2d03110e15a6f7ba1c2e2999f0195f974fa0de8174edf2f09dce8c9f2'
    ]

    list_malicious = []
    list_normal = []

    for file_path in list_file:
        hashes = hash_file(file_path)
        mal = False
        matched_alg = None
        for algorithm, file_hash in hashes.items():
            if file_hash in list2:
                mal = True
                matched_alg = algorithm
                break
        if mal:
            list_malicious.append((file_path,matched_alg))
        else:
            list_normal.append(file_path)

    for file_path in list_normal:
        print(f"Normal files: {file_path}")

    for file_path,algorithm in list_malicious:
        print(f"Malicious files: {file_path}, Algorithm: {algorithm}")