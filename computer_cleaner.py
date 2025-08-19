import os
import sys
import argparse
import logging
import hashlib
import shutil
import time
from pathlib import Path
from collections import defaultdict
import msvcrt

try:
    from send2trash import send2trash  # Safer deletes to Recycle Bin
    HAS_SEND2TRASH = True
except Exception:
    HAS_SEND2TRASH = False

class ComputerCleaner:
    def __init__(self,
                 safe_mode=True,
                 permanent_delete=False,
                 min_file_age_days=1,
                 max_temp_file_size=50 * 1024 * 1024,
                 backup_max_mb=10,
                 exclude_dirs=None):
        self.safe_mode = safe_mode
        self.permanent_delete = permanent_delete
        self.files_to_delete = []
        self.files_to_move = []
        self.delete_reasons = {}  # path -> reason (e.g., 'temp', 'duplicate')

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

        # Limits and thresholds
        self.max_file_size = max_temp_file_size  # limit for temp file deletion
        self.min_file_age_days = min_file_age_days  # Only delete temp files older than X days
        self.backup_max_bytes = int(backup_max_mb) * 1024 * 1024

        # Paths and excludes
        self.cwd_backup_dir = os.path.join(os.getcwd(), 'cleanup_backups')
        self.user_excluded_directories = set(self._normalize_path(p) for p in (exclude_dirs or []))

        # Known temp locations
        self.temp_locations = [
            os.path.expandvars(r'%TEMP%'),
            os.path.expandvars(r'%TMP%'),
            r'C:\Windows\Temp',
            os.path.expandvars(r'%LOCALAPPDATA%\Temp'),
        ]
        self.temp_locations_normalized = [self._normalize_path(p) for p in self.temp_locations if p]

        # Setup logging to LocalAppData to avoid permission issues and keep project folder clean
        log_dir = os.path.join(os.environ.get('LOCALAPPDATA', os.getcwd()), 'CompCleaner', 'logs')
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, 'cleaner.log')
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_path),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _normalize_path(self, path_str):
        try:
            return os.path.normcase(os.path.abspath(path_str))
        except Exception:
            return os.path.normcase(path_str)

    def _is_under_dir(self, path_str, dir_str):
        try:
            path_norm = self._normalize_path(path_str)
            dir_norm = self._normalize_path(dir_str)
            return os.path.commonpath([path_norm, dir_norm]) == dir_norm
        except Exception:
            return False

    def _is_in_known_temp(self, path_str):
        path_norm = self._normalize_path(path_str)
        for temp_dir in self.temp_locations_normalized:
            if temp_dir and self._is_under_dir(path_norm, temp_dir):
                return True
        return False

    def _is_file_in_use(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                try:
                    # Try non-blocking lock of 1 byte; if it fails, file is likely in use
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                    return False
                except (OSError, IOError, PermissionError):
                    return True
        except (OSError, IOError, PermissionError):
            return True

    def _should_skip_dir(self, dir_path):
        try:
            if not dir_path:
                return True
            full = self._normalize_path(dir_path)
            # Skip backups, user excludes, and common noisy folders
            if self._is_under_dir(full, self.cwd_backup_dir):
                return True
            if full in self.user_excluded_directories:
                return True
            base = os.path.basename(full)
            if base in {'.git', 'node_modules', '__pycache__'}:
                return True
            if os.path.islink(dir_path):
                return True
        except Exception:
            return False
        return False

    def _add_file_to_delete(self, file_path, reason):
        if file_path not in self.delete_reasons:
            self.files_to_delete.append(file_path)
            self.delete_reasons[file_path] = reason
    
    def is_safe_to_delete(self, file_path, override_size_check=False):
        """Check if a file is safe to delete"""
        try:
            file_path_normalized = self._normalize_path(file_path)

            # Do not delete within protected directories unless it's clearly within known temp locations
            for protected_dir in self.protected_directories:
                if self._is_under_dir(file_path_normalized, protected_dir) and not self._is_in_known_temp(file_path_normalized):
                    return False

            # Check file extension
            file_ext = Path(file_path).suffix.lower()
            if file_ext in self.protected_extensions and not (
                self._is_in_known_temp(file_path) or any(ind in file_path.lower() for ind in ['temp', 'tmp', 'cache', '.old', '.bak', '.backup'])
            ):
                return False

            # Check file size (unless explicitly overridden, e.g., for duplicates)
            try:
                if not override_size_check and os.path.getsize(file_path) > self.max_file_size:
                    self.logger.warning(f"Skipping large file due to size limit: {file_path}")
                    return False
            except OSError:
                return False

            # Check if file is currently in use
            if self._is_file_in_use(file_path):
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
            backup_dir = self.cwd_backup_dir
            os.makedirs(backup_dir, exist_ok=True)
            
            # Create a timestamp for the backup
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            backup_filename = f"{timestamp}_{os.path.basename(file_path)}"
            backup_path = os.path.join(backup_dir, backup_filename)
            
            # Only backup files smaller than configured limit to avoid filling up disk
            if os.path.getsize(file_path) < self.backup_max_bytes:
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
        temp_extensions = ['.tmp', '.temp', '.log', '.cache', '.bak', '.old']
        
        for temp_dir in self.temp_locations:
            if os.path.exists(temp_dir):
                try:
                    for root, dirs, files in os.walk(temp_dir):
                        # Prune directories we should skip
                        dirs[:] = [d for d in dirs if not self._should_skip_dir(os.path.join(root, d))]
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
                                    self._add_file_to_delete(file_path, reason='temp')
                                    
                            except (OSError, IOError):
                                continue
                                
                except (PermissionError, OSError) as e:
                    self.logger.warning(f"Cannot access {temp_dir}: {e}")
        
        self.logger.info(f"Found {len(self.files_to_delete)} temporary files to delete")

    def find_duplicates(self, directory):
        """Find duplicate files in directory"""
        size_to_paths = defaultdict(list)
        file_hashes = defaultdict(list)
        duplicates_found = 0
        
        if not os.path.exists(directory):
            self.logger.error(f"Directory {directory} does not exist")
            return
            
        self.logger.info(f"Scanning for duplicates in {directory}")
        
        for root, dirs, files in os.walk(directory):
            # Prune directories we should skip
            dirs[:] = [d for d in dirs if not self._should_skip_dir(os.path.join(root, d))]
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # Skip if file is too large (>100MB) for performance
                    if os.path.getsize(file_path) > 100 * 1024 * 1024:
                        continue

                    size_to_paths[os.path.getsize(file_path)].append(file_path)
                        
                except (OSError, IOError, PermissionError) as e:
                    self.logger.warning(f"Cannot process {file_path}: {e}")
                    continue
        
        def compute_md5(path, chunk_size=1024 * 1024):
            md5 = hashlib.md5()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(chunk_size), b''):
                    md5.update(chunk)
            return md5.hexdigest()

        # For sizes with more than one file, compute hashes
        for size, paths in size_to_paths.items():
            if len(paths) < 2:
                continue
            for p in paths:
                try:
                    h = compute_md5(p)
                    file_hashes[h].append(p)
                except (OSError, IOError, PermissionError) as e:
                    self.logger.warning(f"Cannot hash {p}: {e}")
                    continue

        # Find actual duplicates (hash appears more than once)
        for file_hash, paths in file_hashes.items():
            if len(paths) > 1:
                # Keep the newest file (by mtime), mark others for deletion
                try:
                    paths_sorted = sorted(paths, key=lambda p: os.path.getmtime(p), reverse=True)
                except Exception:
                    paths_sorted = list(paths)
                for duplicate_path in paths_sorted[1:]:
                    self._add_file_to_delete(duplicate_path, reason='duplicate')
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
            # Do not descend into target category folders to avoid self-interference
            if os.path.normcase(self._normalize_path(root)) == os.path.normcase(self._normalize_path(directory)):
                dirs[:] = [d for d in dirs if d not in file_types.keys() and not self._should_skip_dir(os.path.join(root, d))]
            else:
                dirs[:] = [d for d in dirs if not self._should_skip_dir(os.path.join(root, d))]
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
                    if not self._is_under_dir(file_path, str(target_dir)):
                        new_path = target_dir / file
                        move_pair = (file_path, str(new_path))
                        if move_pair not in self.files_to_move:
                            self.files_to_move.append(move_pair)
                            organized_count += 1
        
        self.logger.info(f"Found {organized_count} files to organize")

    def preview_cleanup(self):
        """Show what will be cleaned without doing it"""
        print(f"\n[CLEANUP PREVIEW]")
        print(f"==================")
        
        unique_deletes = list(dict.fromkeys(self.files_to_delete))
        unique_moves = list(dict.fromkeys(self.files_to_move))

        if unique_deletes:
            total_size = 0
            large_files = []
            protected_files = []
            
            for file_path in unique_deletes:
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
            
            print(f"Files to delete: {len(unique_deletes)}")
            print(f"Total size: {total_size / (1024*1024):.1f} MB")
            
            if large_files:
                print(f"WARNING: Large files (>1MB) that will be backed up:")
                for file_path, size in sorted(large_files, key=lambda x: x[1], reverse=True)[:5]:  # Show top 5
                    print(f"   {file_path} ({size/(1024*1024):.1f} MB)")
                if len(large_files) > 5:
                    print(f"   ... and {len(large_files)-5} more")
            
            if protected_files:
                print(f"PROTECTED: Extension files (will be backed up):")
                for file_path in sorted(protected_files)[:3]:  # Show first 3
                    print(f"   {file_path}")
                if len(protected_files) > 3:
                    print(f"   ... and {len(protected_files)-3} more")
        
        if unique_moves:
            print(f"\nFiles to organize: {len(unique_moves)}")
            move_summary = {}
            for old_path, new_path in unique_moves:
                category = os.path.basename(os.path.dirname(new_path))
                move_summary[category] = move_summary.get(category, 0) + 1
            
            for category, count in move_summary.items():
                print(f"   {category}: {count} files")
        
        if not unique_deletes and not unique_moves:
            print("Nothing to clean up!")
            
        print("==================")

    def execute_cleanup(self):
        """Actually perform the cleanup"""
        if self.safe_mode:
            print(f"\n[CLEANUP SUMMARY]")
            print(f"   Files to delete: {len(set(self.files_to_delete))}")
            print(f"   Files to move: {len(set(self.files_to_move))}")
            print(f"   Backup directory: {self.cwd_backup_dir}")
            response = input("\nProceed with cleanup? Type 'YES' to confirm: ")
            if response.strip().lower() not in {'yes', 'y'}:
                print("Cleanup aborted.")
                return
        
        deleted_count = 0
        moved_count = 0
        backed_up_count = 0
        
        unique_deletes = list(dict.fromkeys(self.files_to_delete))
        unique_moves = list(dict.fromkeys(self.files_to_move))

        # Execute deletions with safety checks
        for file_path in unique_deletes:
            try:
                if not os.path.exists(file_path):
                    continue
                
                # Double-check safety before deletion
                is_duplicate = self.delete_reasons.get(file_path) == 'duplicate'
                if not self.is_safe_to_delete(file_path, override_size_check=is_duplicate):
                    self.logger.warning(f"Safety check failed, skipping: {file_path}")
                    continue
                
                # Create backup for files that might be important
                file_ext = Path(file_path).suffix.lower()
                if (file_ext in self.protected_extensions or 
                    os.path.getsize(file_path) > 1024 * 1024):  # Files > 1MB
                    backup_path = self.create_backup(file_path)
                    if backup_path:
                        backed_up_count += 1
                
                # Delete: send to Recycle Bin by default if available
                if self.permanent_delete or not HAS_SEND2TRASH:
                    os.remove(file_path)
                else:
                    try:
                        send2trash(file_path)
                    except Exception:
                        # Fallback to permanent delete if send2trash fails
                        os.remove(file_path)
                self.logger.info(f"Deleted: {file_path}")
                deleted_count += 1
                
            except (OSError, IOError, PermissionError) as e:
                self.logger.error(f"Cannot delete {file_path}: {e}")
        
        # Execute moves with safety checks
        for old_path, new_path in unique_moves:
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
            print(f"   Backups saved to: {self.cwd_backup_dir}")

def main():
    parser = argparse.ArgumentParser(description="Clean up your computer")
    parser.add_argument('--no-safe-mode', action='store_true',
                        help="Skip confirmation prompts")
    parser.add_argument('--permanent', action='store_true',
                        help='Permanently delete files instead of sending to Recycle Bin')
    parser.add_argument('--age-days', type=int, default=1, metavar='N',
                        help='Minimum age in days for temp file deletion (default: 1)')
    parser.add_argument('--max-temp-size-mb', type=int, default=50, metavar='MB',
                        help='Max size in MB for temp file deletion (default: 50)')
    parser.add_argument('--backup-max-mb', type=int, default=10, metavar='MB',
                        help='Max size in MB for backups (default: 10)')
    parser.add_argument('--exclude', action='append', default=None, metavar='DIR',
                        help='Exclude a directory (can be specified multiple times)')
    parser.add_argument('--preview-only', action='store_true',
                        help='Only show what would be cleaned')
    parser.add_argument('--find-duplicates', type=str, metavar='DIRECTORY',
                        help='Find and remove duplicate files in specified directory')
    parser.add_argument('--organize', type=str, metavar='DIRECTORY',
                        help='Organize files by type in specified directory')
    parser.add_argument('--temp-only', action='store_true',
                        help='Only clean temporary files')
    
    args = parser.parse_args()

    cleaner = ComputerCleaner(
        safe_mode=not args.no_safe_mode,
        permanent_delete=args.permanent,
        min_file_age_days=args.age_days,
        max_temp_file_size=args.max_temp_size_mb * 1024 * 1024,
        backup_max_mb=args.backup_max_mb,
        exclude_dirs=args.exclude or []
    )

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