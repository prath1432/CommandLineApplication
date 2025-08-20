import os
import random
import shutil
import logging
import platform
from tkinter import Tk, filedialog
from datetime import datetime
import concurrent.futures

# Set up logging
def setup_logging():
    with open('securewipe.log', 'a') as log_file:
        log_file.write(f"\n=== SecureWipe Run - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")

logging.basicConfig(filename='securewipe.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def clear_terminal():
    
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def choose_files():
    
    root = Tk()
    root.withdraw()  
    files = filedialog.askopenfilenames(title="Select files to delete")
    root.destroy()
    return files

def choose_directory():
    
    root = Tk()
    root.withdraw()  
    directory = filedialog.askdirectory(title="Select directory to delete")
    root.destroy()
    return directory

def choose_specific_files_from_directory(directory):
    
    root = Tk()
    root.withdraw()
    files = filedialog.askopenfilenames(initialdir=directory, title="Select files to delete")
    root.destroy()
    return files

def create_backup(filepath_or_directory):
    
    backup_dir = filedialog.askdirectory(title="Select backup location")
    if not backup_dir:
        return None

    if os.path.isfile(filepath_or_directory):
        shutil.copy(filepath_or_directory, backup_dir)
    elif os.path.isdir(filepath_or_directory):
        shutil.copytree(filepath_or_directory, os.path.join(backup_dir, os.path.basename(filepath_or_directory)))

    logging.info(f"Backup created at {backup_dir} for {filepath_or_directory}")
    return backup_dir

def overwrite_file(filepath, passes):
    file_size = os.path.getsize(filepath)
    pass_data_filename = f"{os.path.basename(filepath)}_pass.txt"
    pass_data_filepath = os.path.join(os.path.dirname(filepath), pass_data_filename)

    try:
        with open(filepath, 'r+b') as f, open(pass_data_filepath, 'w') as pass_log:
            for i in range(passes):
                f.seek(0)
                random_data = os.urandom(file_size)
                f.write(random_data)
                pass_log.write(f"Pass {i + 1}: {random_data.hex()}\n")
                logging.info(f"Overwriting {filepath} - Pass {i + 1} of {passes}")
                print(f"Overwriting {filepath} - Pass {i + 1} of {passes} completed. ✔️")
        
        os.remove(filepath)
        os.remove(pass_data_filepath)  
        logging.info(f"{filepath} has been securely deleted after {passes} passes.")
        print(f"{filepath} has been securely deleted after {passes} passes. 🗑️")

        return filepath, None

    except FileNotFoundError as e:
        logging.error(f"Error: File not found {filepath} - {e}")
        print(f"Error: File not found {filepath}. It may have been moved or deleted. ❌")
        return None, None
    except Exception as e:
        logging.error(f"Unexpected error occurred while overwriting file {filepath} - {e}")
        print(f"Unexpected error occurred: {e} ⚠️")
        return None, None

def sanitize_directory(directory, passes, delete_subdirs=False):
    
    deleted_files = []
    deleted_dirs = []

    for root, dirs, files in os.walk(directory, topdown=False):
        for file in files:
            filepath = os.path.join(root, file)
            result, _ = overwrite_file(filepath, passes)
            if result:
                deleted_files.append(result)
        if delete_subdirs:
            for dir in dirs:
                subdir_path = os.path.join(root, dir)
                deleted_files.extend(sanitize_directory(subdir_path, passes, delete_subdirs=True))
            deleted_dirs.append(root)

    shutil.rmtree(directory)
    deleted_dirs.append(directory)
    logging.info(f"Directory {directory} has been securely deleted after {passes} passes.")
    print(f"Directory {directory} has been securely deleted after {passes} passes. 🗑️")

    return deleted_files, deleted_dirs

def parallel_delete(filepaths, passes):
    deleted_files = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(lambda p: overwrite_file(p, passes), filepath) for filepath in filepaths]
        for future in concurrent.futures.as_completed(futures):
            result, _ = future.result()
            if result:
                deleted_files.append(result)
    return deleted_files

def create_summary_file(deleted_files, deleted_dirs):
    summary_filename = 'deleted_files_summary.txt'
    with open(summary_filename, 'a') as summary_file:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        summary_file.write(f"\n=== Operation at {timestamp} ===\n")
        summary_file.write("Deleted Files:\n")
        for file in deleted_files:
            summary_file.write(f"{file}\n")
        summary_file.write("\nDeleted Directories:\n")
        for directory in deleted_dirs:
            summary_file.write(f"{directory}\n")
    logging.info(f"Summary updated: {summary_filename}")
    print(f"Summary updated: {summary_filename} 📄")

def secure_delete():
    clear_terminal()
    setup_logging()

    print("\n🎉 Welcome to SecureWipe - Your Secure File Deletion Tool 🎉")

    while True:
        print("\n=== SecureWipe - Secure File Deletion ===")
        print("Choose the operation you'd like to perform:\n")
        print("1. Delete single files")
        print("2. Delete all files in a directory")
        print("3. Delete specific files from a directory")
        print("4. Exit\n")

        choice = input("Enter your choice (1/2/3/4): ").strip()

        if choice == '4':
            print("Goodbye! 👋")
            break

        
        try:
            passes = int(input("Enter the number of passes for overwriting (recommended: 3 or 7): ").strip())
            if passes <= 0:
                print("Error: Number of passes must be greater than 0.")
                continue
        except ValueError:
            print("Error: Please enter a valid number of passes.")
            continue

        if choice == '1':
            files = choose_files()
            if not files:
                print("Error: No files selected. Please try again.")
                continue
            
            confirm = input(f"Are you sure you want to delete the selected files? (yes/no): ").strip().lower()
            if confirm != 'yes':
                print("Operation cancelled. ❌")
                continue

            backup_choice = input("Do you want to create backups of the selected files before deletion? (yes/no): ").strip().lower()
            if backup_choice == 'yes':
                for file in files:
                    create_backup(file)

            deleted_files = parallel_delete(files, passes)
            create_summary_file(deleted_files, [])

        elif choice == '2':
            directory = choose_directory()
            if not directory or not os.path.isdir(directory):
                print("Error: No valid directory selected. Please try again.")
                continue

            confirm = input(f"Are you sure you want to delete all files in the selected directory? (yes/no): ").strip().lower()
            if confirm != 'yes':
                print("Operation cancelled. ❌")
                continue

            backup_choice = input(f"Do you want to create a backup of the selected directory before deletion? (yes/no): ").strip().lower()
            if backup_choice == 'yes':
                create_backup(directory)

            deleted_files, deleted_dirs = sanitize_directory(directory, passes, delete_subdirs=True)
            create_summary_file(deleted_files, deleted_dirs)

        elif choice == '3':
            directory = choose_directory()
            if not directory or not os.path.isdir(directory):
                print("Error: No valid directory selected. Please try again.")
                continue

            files_to_delete = choose_specific_files_from_directory(directory)
            if not files_to_delete:
                print("Error: No files selected. Please try again.")
                continue
            
            confirm = input(f"Are you sure you want to delete the selected files in {directory}? (yes/no): ").strip().lower()
            if confirm != 'yes':
                print("Operation cancelled. ❌")
                continue

            backup_choice = input(f"Do you want to create backups of the selected files before deletion? (yes/no): ").strip().lower()
            if backup_choice == 'yes':
                for file in files_to_delete:
                    create_backup(file)

            deleted_files = parallel_delete(files_to_delete, passes)
            create_summary_file(deleted_files, [])

        else:
            print("Error: Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    secure_delete()
