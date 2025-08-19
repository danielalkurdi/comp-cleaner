import os
import sys
import argparse
import logging
import hashlib
import shutil
import time
from pathlib import Path
from collections import defaultdict

class ComputerCleaner:
    def __init__(self, safe_mode=True):
        self.safe_mode = safe_mode
        self.files_to_delete = []
        self.files_to_move = []
        
        # Safety configurations
        self.protected_extensions = {
            '.exe', '.dll', '.sys', '.bat', '.cmd', '.com', '.scr', '.msi', '.reg',
            '.py', '.js', '.html', '.css', '.php', '.java', '.cpp', '.c', '.h',
            '.docx', '.xlsx', '.pptx', '.pdf', '.txt', '.md', '.json', '.xml',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp',
            '.mp4', '.avi', '.mkv', '.mov', '.mp3', '.wav', '.flac'
        }
        
        self.protected_directories = {
            r'C:\Windows\System32',
            r'C:\Windows\SysWOW64',
            r'C:\Program Files',
            r'C:\Program Files (x86)',
            os.path.expandvars(r'%APPDATA%'),
            os.path.expandvars(r'%PROGRAMDATA%'),
            os.path.expandvars(r'%USERPROFILE%\Documents'),
            os.path.expandvars(r'%USERPROFILE%\Desktop'),
            os.path.expandvars(r'%USERPROFILE%\Pictures'),
            os.path.expandvars(r'%USERPROFILE%\Videos'),
            os.path.expandvars(r'%USERPROFILE%\Music')
        }
        
        self.max_file_size = 50 * 1024 * 1024  # 50MB limit for temp file deletion
        self.min_file_age_days = 1  # Only delete temp files older than 1 day

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('cleaner.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def is_safe_to_delete(self, file_path):
        """Check if a file is safe to delete"""
        try:
            # Check if file is in a protected directory
            file_path_normalized = os.path.normpath(file_path)
            for protected_dir in self.protected_directories:
                if file_path_normalized.startswith(os.path.normpath(protected_dir)):
                    if not any(temp_dir in file_path_normalized for temp_dir in ['Temp', 'Cache', 'tmp']):
                        return False
            
            # Check file extension
            file_ext = Path(file_path).suffix.lower()
            if file_ext in self.protected_extensions:
                # Only allow deletion if it's clearly a temp file
                if not any(temp_indicator in file_path.lower() for temp_indicator in [
                    'temp', 'tmp', 'cache', '.old', '.bak', '.backup'
                ]):
                    return False
            
            # Check file size
            try:
                if os.path.getsize(file_path) > self.max_file_size:
                    self.logger.warning(f"Skipping large file: {file_path}")
                    return False
            except OSError:
                return False
                
            # Check if file is currently in use
            try:
                with open(file_path, 'r+b'):
                    pass
            except (IOError, OSError, PermissionError):
                self.logger.warning(f"File may be in use, skipping: {file_path}")
                return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking file safety {file_path}: {e}")
            return False
    
    def is_temp_file_old_enough(self, file_path):
        """Check if temp file is old enough to be safely deleted"""
        try:
            file_age = time.time() - os.path.getmtime(file_path)
            return file_age > (self.min_file_age_days * 24 * 3600)
        except OSError:
            return False
    
    def create_backup(self, file_path):
        """Create a backup of important files before deletion"""
        try:
            backup_dir = os.path.join(os.getcwd(), 'cleanup_backups')
            os.makedirs(backup_dir, exist_ok=True)
            
            # Create a timestamp for the backup
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            backup_filename = f"{timestamp}_{os.path.basename(file_path)}"
            backup_path = os.path.join(backup_dir, backup_filename)
            
            # Only backup files smaller than 10MB to avoid filling up disk
            if os.path.getsize(file_path) < 10 * 1024 * 1024:
                shutil.copy2(file_path, backup_path)
                self.logger.info(f"Backed up: {file_path} -> {backup_path}")
                return backup_path
            else:
                self.logger.info(f"File too large for backup: {file_path}")
                
        except Exception as e:
            self.logger.error(f"Failed to backup {file_path}: {e}")
        
        return None
    
    def find_temp_files(self):
        """Find temporary files to clean"""
        temp_locations = [
            os.path.expandvars(r'%TEMP%'),
            os.path.expandvars(r'%TMP%'),
            r'C:\Windows\Temp',
            os.path.expandvars(r'%LOCALAPPDATA%\Temp'),
        ]
        
        temp_extensions = ['.tmp', '.temp', '.log', '.cache', '.bak', '.old']
        
        for temp_dir in temp_locations:
            if os.path.exists(temp_dir):
                try:
                    for root, dirs, files in os.walk(temp_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            
                            try:
                                # Check if file is safe to delete and old enough
                                if not self.is_safe_to_delete(file_path):
                                    continue
                                
                                if not self.is_temp_file_old_enough(file_path):
                                    continue
                                
                                # Check by extension or age
                                if (any(file.lower().endswith(ext) for ext in temp_extensions) or 
                                    os.path.getmtime(file_path) < (time.time() - 7 * 24 * 3600)):
                                    self.files_to_delete.append(file_path)
                                    
                            except (OSError, IOError):
                                continue
                                
                except (PermissionError, OSError) as e:
                    self.logger.warning(f"Cannot access {temp_dir}: {e}")
        
        self.logger.info(f"Found {len(self.files_to_delete)} temporary files to delete")

    def find_duplicates(self, directory):
        """Find duplicate files in directory"""
        file_hashes = defaultdict(list)
        duplicates_found = 0
        
        if not os.path.exists(directory):
            self.logger.error(f"Directory {directory} does not exist")
            return
            
        self.logger.info(f"Scanning for duplicates in {directory}")
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # Skip if file is too large (>100MB) for performance
                    if os.path.getsize(file_path) > 100 * 1024 * 1024:
                        continue
                        
                    # Calculate MD5 hash
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.md5(f.read()).hexdigest()
                        file_hashes[file_hash].append(file_path)
                        
                except (OSError, IOError, PermissionError) as e:
                    self.logger.warning(f"Cannot process {file_path}: {e}")
                    continue
        
        # Find actual duplicates (hash appears more than once)
        for file_hash, paths in file_hashes.items():
            if len(paths) > 1:
                # Keep the first file, mark others for deletion
                for duplicate_path in paths[1:]:
                    self.files_to_delete.append(duplicate_path)
                    duplicates_found += 1
                    
        self.logger.info(f"Found {duplicates_found} duplicate files")

    def organise_files(self, directory):
        """Organise files by type"""
        if not os.path.exists(directory):
            self.logger.error(f"Directory {directory} does not exist")
            return
            
        file_types = {
            'Images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp'],
            'Documents': ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt', '.xls', '.xlsx', '.ppt', '.pptx'],
            'Videos': ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v'],
            'Audio': ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a'],
            'Archives': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'],
            'Code': ['.py', '.js', '.html', '.css', '.cpp', '.java', '.c', '.php', '.rb', '.go']
        }
        
        organized_count = 0
        base_path = Path(directory)
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = Path(file).suffix.lower()
                
                # Find which category this file belongs to
                target_folder = None
                for category, extensions in file_types.items():
                    if file_ext in extensions:
                        target_folder = category
                        break
                
                if target_folder:
                    # Create target directory if it doesn't exist
                    target_dir = base_path / target_folder
                    
                    # Only move if file is not already in the target folder
                    if not str(file_path).startswith(str(target_dir)):
                        new_path = target_dir / file
                        self.files_to_move.append((file_path, str(new_path)))
                        organized_count += 1
        
        self.logger.info(f"Found {organized_count} files to organize")

    def preview_cleanup(self):
        """Show what will be cleaned without doing it"""
        print(f"\n[CLEANUP PREVIEW]")
        print(f"==================")
        
        if self.files_to_delete:
            total_size = 0
            large_files = []
            protected_files = []
            
            for file_path in self.files_to_delete:
                try:
                    size = os.path.getsize(file_path)
                    total_size += size
                    
                    if size > 1024 * 1024:  # Files > 1MB
                        large_files.append((file_path, size))
                    
                    file_ext = Path(file_path).suffix.lower()
                    if file_ext in self.protected_extensions:
                        protected_files.append(file_path)
                        
                except OSError:
                    continue
            
            print(f"Files to delete: {len(self.files_to_delete)}")
            print(f"Total size: {total_size / (1024*1024):.1f} MB")
            
            if large_files:
                print(f"WARNING: Large files (>1MB) that will be backed up:")
                for file_path, size in large_files[:5]:  # Show first 5
                    print(f"   {file_path} ({size/(1024*1024):.1f} MB)")
                if len(large_files) > 5:
                    print(f"   ... and {len(large_files)-5} more")
            
            if protected_files:
                print(f"PROTECTED: Extension files (will be backed up):")
                for file_path in protected_files[:3]:  # Show first 3
                    print(f"   {file_path}")
                if len(protected_files) > 3:
                    print(f"   ... and {len(protected_files)-3} more")
        
        if self.files_to_move:
            print(f"\nFiles to organize: {len(self.files_to_move)}")
            move_summary = {}
            for old_path, new_path in self.files_to_move:
                category = os.path.basename(os.path.dirname(new_path))
                move_summary[category] = move_summary.get(category, 0) + 1
            
            for category, count in move_summary.items():
                print(f"   {category}: {count} files")
        
        if not self.files_to_delete and not self.files_to_move:
            print("Nothing to clean up!")
            
        print("==================")

    def execute_cleanup(self):
        """Actually perform the cleanup"""
        if self.safe_mode:
            print(f"\n[CLEANUP SUMMARY]")
            print(f"   Files to delete: {len(self.files_to_delete)}")
            print(f"   Files to move: {len(self.files_to_move)}")
            print(f"   Backup directory: {os.path.join(os.getcwd(), 'cleanup_backups')}")
            response = input("\nProceed with cleanup? Type 'YES' to confirm: ")
            if response != 'YES':
                print("Cleanup aborted.")
                return
        
        deleted_count = 0
        moved_count = 0
        backed_up_count = 0
        
        # Execute deletions with safety checks
        for file_path in self.files_to_delete:
            try:
                if not os.path.exists(file_path):
                    continue
                
                # Double-check safety before deletion
                if not self.is_safe_to_delete(file_path):
                    self.logger.warning(f"Safety check failed, skipping: {file_path}")
                    continue
                
                # Create backup for files that might be important
                file_ext = Path(file_path).suffix.lower()
                if (file_ext in self.protected_extensions or 
                    os.path.getsize(file_path) > 1024 * 1024):  # Files > 1MB
                    backup_path = self.create_backup(file_path)
                    if backup_path:
                        backed_up_count += 1
                
                os.remove(file_path)
                self.logger.info(f"Deleted: {file_path}")
                deleted_count += 1
                
            except (OSError, IOError, PermissionError) as e:
                self.logger.error(f"Cannot delete {file_path}: {e}")
        
        # Execute moves with safety checks
        for old_path, new_path in self.files_to_move:
            try:
                if not os.path.exists(old_path):
                    continue
                
                # Create target directory if it doesn't exist
                os.makedirs(os.path.dirname(new_path), exist_ok=True)
                
                # Handle file name conflicts
                counter = 1
                original_new_path = new_path
                while os.path.exists(new_path):
                    name, ext = os.path.splitext(original_new_path)
                    new_path = f"{name}_{counter}{ext}"
                    counter += 1
                
                shutil.move(old_path, new_path)
                self.logger.info(f"Moved: {old_path} -> {new_path}")
                moved_count += 1
                
            except (OSError, IOError, PermissionError) as e:
                self.logger.error(f"Cannot move {old_path}: {e}")
        
        print(f"\n[CLEANUP COMPLETED]")
        print(f"   Deleted: {deleted_count} files")
        print(f"   Moved: {moved_count} files") 
        print(f"   Backed up: {backed_up_count} files")
        if backed_up_count > 0:
            print(f"   Backups saved to: {os.path.join(os.getcwd(), 'cleanup_backups')}")

def main():
    parser = argparse.ArgumentParser(description="Clean up your computer")
    parser.add_argument('--no-safe-mode', action='store_true',
                        help="Skip confirmation prompts")
    parser.add_argument('--preview-only', action='store_true',
                        help='Only show what would be cleaned')
    parser.add_argument('--find-duplicates', type=str, metavar='DIRECTORY',
                        help='Find and remove duplicate files in specified directory')
    parser.add_argument('--organize', type=str, metavar='DIRECTORY',
                        help='Organize files by type in specified directory')
    parser.add_argument('--temp-only', action='store_true',
                        help='Only clean temporary files')
    
    args = parser.parse_args()

    cleaner = ComputerCleaner(safe_mode=not args.no_safe_mode)

    print("Starting computer cleanup...")

    # Run cleanup operations based on arguments
    if args.temp_only or not (args.find_duplicates or args.organize):
        cleaner.find_temp_files()
    
    if args.find_duplicates:
        cleaner.find_duplicates(args.find_duplicates)
    
    if args.organize:
        cleaner.organise_files(args.organize)

    if args.preview_only:
        cleaner.preview_cleanup()
    else:
        cleaner.preview_cleanup()
        if len(cleaner.files_to_delete) > 0 or len(cleaner.files_to_move) > 0:
            cleaner.execute_cleanup()
        else:
            print("Nothing to clean up!")

if __name__ == "__main__":
    main()