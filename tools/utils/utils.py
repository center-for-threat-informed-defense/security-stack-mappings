import os

def dir_path(path):
    if os.path.isdir(path):
        return path
    else:
        raise NotADirectoryError(path)


def file_path(path):
    if os.path.isfile(path):
        return path
    else:
        raise NotAFileError(path)


def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))
