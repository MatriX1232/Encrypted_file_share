import os


def list_files(path: str) -> list:
    """
    Lists all files in a directory.
    :param path: Directory path
    :return: List of file names
    """
    try:
        return [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
    except FileNotFoundError:
        print(f"Directory {path} not found.")
        return []
    except PermissionError:
        print(f"Permission denied to access {path}.")
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []
    

if __name__ == "__main__":
    # Example usage
    path = "."  # Current directory
    files = list_files(path)
    print("Files in directory:", files)