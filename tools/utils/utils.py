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
