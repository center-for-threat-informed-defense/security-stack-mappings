import os
from pathlib import Path

def dir_path(path):
    if os.path.isdir(path):
        return path
    else:
        raise NotADirectoryError(path)


def file_path(path):
    if os.path.isfile(path):
        return path
    else:
        raise FileNotFoundError(path)


def chunkstring(string, length):
    chunks = string.strip().replace('\n',' ').split(" ")
    final_chunks = []
    working_chunk = ""
    current_len = 0
    for chunk in chunks:
        if (current_len + len(chunk)) <= length:
            working_chunk += f" {chunk}"
            current_len = len(working_chunk)
        else:
            if working_chunk:
                final_chunks.append(working_chunk)
            working_chunk = chunk
            current_len = len(working_chunk)
    
    final_chunks.append(working_chunk)
    return final_chunks


def get_project_root():
    return str(Path(os.path.dirname(__file__)).parent.parent)

