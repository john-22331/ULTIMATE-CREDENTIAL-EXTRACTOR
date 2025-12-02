#!/usr/bin/env python3
"""
ULTIMATE CREDENTIAL EXTRACTOR - DEFENSIVE RESEARCH TOOL
Complete Version with Corporate Email Detection & Progress Tracking
+ SMART DEDUPLICATION & MERGING FEATURE - OPTIMIZED
+ FLEXIBLE EXTRACTION FOR ANY STEALER LOG FORMAT
"""

import os
import re
import threading
import time
import glob
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import json
from dataclasses import dataclass
from typing import List, Dict, Set, DefaultDict, Tuple, Any
from collections import defaultdict
import logging
from difflib import SequenceMatcher

# Enhanced Progress bar implementation (existing code)
class ProgressBar:
    def __init__(self, total, description="Processing"):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = time.time()
        self.lock = threading.Lock()
        self.last_update_time = self.start_time
        self.last_update_current = 0
    
    def update(self, n=1):
        with self.lock:
            self.current += n
            current_time = time.time()
            
            # Only update display every 0.1 seconds to reduce flickering
            if current_time - self.last_update_time >= 0.1 or self.current == self.total:
                self.display()
                self.last_update_time = current_time
                self.last_update_current = self.current
    
    def display(self):
        if self.total == 0:
            return
            
        percent = (self.current / self.total) * 100
        bar_length = 40
        filled_length = int(bar_length * self.current // self.total)
        bar = '█' * filled_length + '─' * (bar_length - filled_length)
        
        elapsed_time = time.time() - self.start_time
        if self.current > 0:
            # Calculate speed based on last update to get more accurate current speed
            recent_elapsed = time.time() - self.last_update_time
            recent_processed = self.current - self.last_update_current
            if recent_elapsed > 0:
                items_per_second = recent_processed / recent_elapsed
            else:
                items_per_second = self.current / elapsed_time
            
            estimated_total = elapsed_time * self.total / self.current
            remaining = estimated_total - elapsed_time
            
            # Format time nicely
            if remaining > 3600:
                eta_str = f"{remaining/3600:.1f}h"
            elif remaining > 60:
                eta_str = f"{remaining/60:.1f}m"
            else:
                eta_str = f"{remaining:.1f}s"
                
            # Format numbers with commas for thousands
            current_str = f"{self.current:,}"
            total_str = f"{self.total:,}"
            speed_str = f"{items_per_second:,.1f}"
        else:
            current_str = "0"
            total_str = f"{self.total:,}"
            speed_str = "0.0"
            eta_str = "N/A"
        
        print(f'\r{self.description}: |{bar}| {percent:.1f}% ({current_str}/{total_str}) '
              f'[{speed_str} lines/s] ETA: {eta_str}', end='', flush=True)
    
    def close(self):
        print()  # Move to next line

# NEW: Smart Deduplication Engine - OPTIMIZED
class SmartDeduplication:
    """Advanced deduplication with multiple strategies and fuzzy matching - OPTIMIZED"""
    
    def __init__(self):
        self.deduplication_stats = {
            'total_processed': 0,
            'exact_duplicates_removed': 0,
            'email_duplicates_resolved': 0,
            'fuzzy_matches_found': 0,
            'domain_consolidations': 0,
            'final_unique_count': 0
        }
        
        # Configuration for deduplication strategies
        self.strategies = {
            'exact': True,
            'email_based': True,
            'fuzzy_matching': False,  # Disabled by default for performance
            'domain_consolidation': False
        }
        
        self.merge_strategy = 'keep_newest'  # 'keep_newest', 'keep_oldest', 'keep_strongest'
    
    def set_strategy(self, strategy_config: Dict[str, Any]):
        """Configure deduplication strategies"""
        self.strategies.update(strategy_config)
    
    def set_merge_strategy(self, strategy: str):
        """Set the merge strategy for conflicts"""
        valid_strategies = ['keep_newest', 'keep_oldest', 'keep_strongest', 'keep_all']
        if strategy in valid_strategies:
            self.merge_strategy = strategy
        else:
            raise ValueError(f"Invalid strategy. Choose from: {valid_strategies}")
    
    def exact_deduplicate(self, credentials: List[str]) -> List[str]:
        """Remove exact duplicates (same email:password)"""
        seen = set()
        unique_credentials = []
        
        for cred in credentials:
            if cred not in seen:
                seen.add(cred)
                unique_credentials.append(cred)
        
        removed = len(credentials) - len(unique_credentials)
        self.deduplication_stats['exact_duplicates_removed'] += removed
        self.deduplication_stats['total_processed'] += len(credentials)
        
        return unique_credentials
    
    def email_based_deduplicate(self, credentials: List[str]) -> List[str]:
        """Resolve duplicates where same email has different passwords - OPTIMIZED"""
        if not credentials:
            return []
        
        print("   🔍 Processing email conflicts...")
        
        email_map = {}  # email -> list of (password, original_credential, index)
        
        # Create progress bar for grouping phase
        group_progress = ProgressBar(len(credentials), "Grouping by email")
        
        # Group by email with progress tracking
        for idx, cred in enumerate(credentials):
            try:
                email, password = cred.split(':', 1)
                if email not in email_map:
                    email_map[email] = []
                email_map[email].append((password, cred, idx))
            except ValueError:
                # Skip invalid credentials
                pass
            group_progress.update(1)
        
        group_progress.close()
        
        resolved_credentials = []
        conflicts_resolved = 0
        total_emails = len(email_map)
        
        print(f"   📧 Found {total_emails} unique emails")
        
        # Create progress bar for conflict resolution phase
        resolve_progress = ProgressBar(total_emails, "Resolving conflicts")
        
        for email, entries in email_map.items():
            if len(entries) == 1:
                # No conflict, keep the single entry
                resolved_credentials.append(entries[0][1])
            else:
                # Conflict resolution needed
                conflicts_resolved += len(entries) - 1
                resolved_entry = self._resolve_email_conflict(entries)
                resolved_credentials.append(resolved_entry)
            
            resolve_progress.update(1)
        
        resolve_progress.close()
        
        self.deduplication_stats['email_duplicates_resolved'] += conflicts_resolved
        
        print(f"   ✅ Resolved {conflicts_resolved} email conflicts")
        return resolved_credentials
    
    def _resolve_email_conflict(self, entries: List[Tuple[str, str, int]]) -> str:
        """Resolve conflict when same email has multiple passwords"""
        try:
            if self.merge_strategy == 'keep_all':
                # For keep_all, return the first entry but note this will be called in a context
                # where we're reducing to one entry per email, so keep_all doesn't make sense here
                # Let's default to keep_newest in this case
                return entries[-1][1]
            elif self.merge_strategy == 'keep_newest':
                # Assume later entries are newer (based on list order)
                return entries[-1][1]
            elif self.merge_strategy == 'keep_oldest':
                # Assume earlier entries are older
                return entries[0][1]
            elif self.merge_strategy == 'keep_strongest':
                # Keep the password with highest strength
                strongest_entry = max(entries, key=lambda x: self._password_strength(x[0]))
                return strongest_entry[1]
            
            # Default to keep_newest
            return entries[-1][1]
        except Exception as e:
            # Fallback in case of any error
            print(f"   ⚠️  Error resolving conflict, using fallback: {e}")
            return entries[0][1]
    
    def _password_strength(self, password: str) -> int:
        """Calculate password strength score"""
        score = 0
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'[0-9]', password):
            score += 1
        if re.search(r'[^A-Za-z0-9]', password):
            score += 1
        return score
    
    def fuzzy_deduplicate(self, credentials: List[str], threshold: float = 0.8) -> List[str]:
        """Fuzzy matching for similar emails (typos, variations) - OPTIMIZED"""
        if not credentials:
            return credentials
        
        # Skip fuzzy matching for large datasets (too slow)
        if len(credentials) > 5000:
            print("   ⚠️  Skipping fuzzy matching (too slow for large datasets)")
            return credentials
        
        print("   🔄 Applying fuzzy matching...")
        
        # Extract emails for fuzzy matching
        email_cred_map = {}
        for cred in credentials:
            try:
                email, password = cred.split(':', 1)
                email_cred_map[email] = cred
            except ValueError:
                continue
        
        emails = list(email_cred_map.keys())
        to_remove = set()
        
        # Compare emails for similarity with progress
        fuzzy_progress = ProgressBar(len(emails), "Fuzzy matching")
        
        for i in range(len(emails)):
            if emails[i] in to_remove:
                fuzzy_progress.update(1)
                continue
                
            for j in range(i + 1, len(emails)):
                if emails[j] in to_remove:
                    continue
                    
                similarity = SequenceMatcher(None, emails[i], emails[j]).ratio()
                if similarity >= threshold:
                    # Keep the one that appears more "standard"
                    if self._is_more_standard_email(emails[i], emails[j]):
                        to_remove.add(emails[j])
                    else:
                        to_remove.add(emails[i])
                        break  # Move to next i
            
            fuzzy_progress.update(1)
        
        fuzzy_progress.close()
        
        # Filter out fuzzy duplicates
        filtered_credentials = [email_cred_map[email] for email in emails if email not in to_remove]
        
        self.deduplication_stats['fuzzy_matches_found'] += len(to_remove)
        print(f"   ✅ Fuzzy matches: {len(to_remove)} consolidated")
        return filtered_credentials
    
    def _is_more_standard_email(self, email1: str, email2: str) -> bool:
        """Determine which email looks more standard/legitimate"""
        # Prefer emails without numbers in username (unless they look like years)
        try:
            user1, domain1 = email1.split('@')
            user2, domain2 = email2.split('@')
            
            score1 = self._email_standard_score(user1, domain1)
            score2 = self._email_standard_score(user2, domain2)
            
            return score1 >= score2
        except:
            return True  # Fallback
    
    def _email_standard_score(self, username: str, domain: str) -> int:
        """Score how standard/legitimate an email looks"""
        score = 0
        
        # Username scoring
        if re.match(r'^[a-zA-Z\.]+$', username):  # Only letters and dots
            score += 2
        if re.match(r'^[a-z]+\.[a-z]+$', username):  # first.last format
            score += 1
        if len(username) >= 3 and len(username) <= 20:
            score += 1
        if not re.search(r'\d', username):  # No numbers
            score += 1
        
        # Domain scoring
        common_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']
        if domain in common_domains:
            score += 1
        
        return score
    
    def domain_consolidate(self, credentials: List[str]) -> List[str]:
        """Consolidate by base domain (ignore subdomains)"""
        domain_map = defaultdict(list)
        
        for cred in credentials:
            try:
                email, password = cred.split(':', 1)
                domain = email.split('@')[1]
                
                # Extract base domain (ignore subdomains)
                base_domain = self._extract_base_domain(domain)
                domain_map[base_domain].append(cred)
            except (IndexError, ValueError):
                continue
        
        # For domain consolidation, we keep all credentials but can analyze patterns
        # In future versions, we might implement domain-based filtering
        consolidated = [cred for domain_creds in domain_map.values() for cred in domain_creds]
        
        self.deduplication_stats['domain_consolidations'] += (len(credentials) - len(consolidated))
        return consolidated
    
    def _extract_base_domain(self, domain: str) -> str:
        """Extract base domain from full domain"""
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])  # Get last two parts (e.g., company.com)
        return domain
    
    def smart_deduplicate(self, credentials: List[str]) -> Tuple[List[str], Dict[str, int]]:
        """Apply all configured deduplication strategies"""
        original_count = len(credentials)
        current_creds = credentials.copy()
        
        # Reset stats
        self.deduplication_stats = {
            'total_processed': original_count,
            'exact_duplicates_removed': 0,
            'email_duplicates_resolved': 0,
            'fuzzy_matches_found': 0,
            'domain_consolidations': 0,
            'final_unique_count': 0
        }
        
        print("🔍 Applying smart deduplication...")
        
        # Apply strategies in order
        if self.strategies['exact']:
            current_creds = self.exact_deduplicate(current_creds)
            print(f"   ✅ Exact duplicates: {original_count - len(current_creds)} removed")
        
        if self.strategies['email_based'] and current_creds:
            current_creds = self.email_based_deduplicate(current_creds)
        
        if self.strategies['fuzzy_matching'] and current_creds:
            before = len(current_creds)
            current_creds = self.fuzzy_deduplicate(current_creds)
            print(f"   ✅ Fuzzy matches: {before - len(current_creds)} consolidated")
        
        if self.strategies['domain_consolidation'] and current_creds:
            before = len(current_creds)
            current_creds = self.domain_consolidate(current_creds)
            print(f"   ✅ Domain consolidation: {before - len(current_creds)} processed")
        
        self.deduplication_stats['final_unique_count'] = len(current_creds)
        
        return current_creds, self.deduplication_stats.copy()
    
    def smart_deduplicate_optimized(self, credentials: List[str], show_progress: bool = True) -> Tuple[List[str], Dict[str, int]]:
        """Optimized deduplication for large datasets"""
        original_count = len(credentials)
        
        if original_count == 0:
            return [], {
                'total_processed': 0,
                'exact_duplicates_removed': 0,
                'email_duplicates_resolved': 0,
                'fuzzy_matches_found': 0,
                'domain_consolidations': 0,
                'final_unique_count': 0
            }
        
        # Reset stats
        self.deduplication_stats = {
            'total_processed': original_count,
            'exact_duplicates_removed': 0,
            'email_duplicates_resolved': 0,
            'fuzzy_matches_found': 0,
            'domain_consolidations': 0,
            'final_unique_count': 0
        }
        
        if show_progress:
            print(f"🔍 Applying smart deduplication to {original_count:,} credentials...")
        
        current_creds = credentials
        
        # Apply strategies in order with progress tracking
        if self.strategies['exact']:
            if show_progress:
                print("   🔄 Removing exact duplicates...")
            before = len(current_creds)
            current_creds = self.exact_deduplicate(current_creds)
            removed = before - len(current_creds)
            if show_progress:
                print(f"   ✅ Exact duplicates: {removed:,} removed")
        
        if self.strategies['email_based'] and current_creds:
            current_creds = self.email_based_deduplicate(current_creds)
        
        # Skip fuzzy matching for large datasets as it's too slow
        if self.strategies['fuzzy_matching'] and current_creds:
            if len(current_creds) > 5000:
                if show_progress:
                    print("   ⚠️  Skipping fuzzy matching (disabled for large datasets)")
            else:
                if show_progress:
                    print("   🔄 Applying fuzzy matching...")
                before = len(current_creds)
                current_creds = self.fuzzy_deduplicate(current_creds)
                removed = before - len(current_creds)
                if show_progress:
                    print(f"   ✅ Fuzzy matches: {removed:,} consolidated")
        
        if self.strategies['domain_consolidation'] and current_creds:
            if show_progress:
                print("   🔄 Consolidating domains...")
            before = len(current_creds)
            current_creds = self.domain_consolidate(current_creds)
            removed = before - len(current_creds)
            if show_progress:
                print(f"   ✅ Domain consolidation: {removed:,} processed")
        
        self.deduplication_stats['final_unique_count'] = len(current_creds)
        
        return current_creds, self.deduplication_stats.copy()

# NEW: Merge Manager for Session and File Merging
class MergeManager:
    """Manage merging of multiple extraction sessions and files"""
    
    def __init__(self, deduplication_engine: SmartDeduplication):
        self.deduplication = deduplication_engine
        self.merge_history = []
    
    def merge_sessions(self, sessions: List[Dict], strategy: str = 'keep_newest') -> Tuple[List[str], Dict[str, Any]]:
        """Merge multiple extraction sessions"""
        print(f"🔄 Merging {len(sessions)} sessions with strategy: {strategy}")
        
        all_credentials = []
        session_sources = defaultdict(list)
        
        # Collect all credentials from sessions
        for session in sessions:
            session_id = f"session_{int(session['timestamp'])}"
            
            # Try to load credentials from output files
            session_creds = self._load_session_credentials(session)
            all_credentials.extend(session_creds)
            
            # Track sources for reporting
            for cred in session_creds:
                session_sources[cred].append(session_id)
        
        # Apply deduplication
        self.deduplication.set_merge_strategy(strategy)
        
        # Use optimized method for large datasets
        if len(all_credentials) > 10000:
            print("   🚀 Using optimized deduplication for large dataset...")
            unique_credentials, stats = self.deduplication.smart_deduplicate_optimized(all_credentials)
        else:
            unique_credentials, stats = self.deduplication.smart_deduplicate(all_credentials)
        
        # Prepare merge report
        merge_report = {
            'sessions_merged': len(sessions),
            'total_credentials_before': len(all_credentials),
            'total_credentials_after': len(unique_credentials),
            'duplicates_removed': len(all_credentials) - len(unique_credentials),
            'merge_strategy': strategy,
            'session_ids': [f"session_{int(s['timestamp'])}" for s in sessions],
            'merge_timestamp': time.time()
        }
        
        # Record in history
        self.merge_history.append(merge_report)
        
        return unique_credentials, merge_report
    
    def _load_session_credentials(self, session: Dict) -> List[str]:
        """Load credentials from a session's output files"""
        credentials = []
        
        # Try to load from output files mentioned in session
        for keyword, file_pattern in session.get('output_files', {}).items():
            matching_files = glob.glob(file_pattern.replace('*', '[0-9]*'))
            for file_path in matching_files:
                if os.path.exists(file_path):
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#'):
                                    credentials.append(line)
                    except Exception as e:
                        print(f"⚠️  Warning: Could not read {file_path}: {e}")
        
        return credentials
    
    def merge_files(self, file_paths: List[str], strategy: str = 'keep_newest') -> Tuple[List[str], Dict[str, Any]]:
        """Merge multiple credential files directly"""
        print(f"🔄 Merging {len(file_paths)} files with strategy: {strategy}")
        
        all_credentials = []
        file_sources = defaultdict(list)
        
        # Read all files
        for file_path in file_paths:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_creds = []
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                file_creds.append(line)
                        
                        all_credentials.extend(file_creds)
                        
                        # Track sources
                        for cred in file_creds:
                            file_sources[cred].append(os.path.basename(file_path))
                            
                except Exception as e:
                    print(f"⚠️  Warning: Could not read {file_path}: {e}")
        
        # Apply deduplication
        self.deduplication.set_merge_strategy(strategy)
        
        # Use optimized method for large datasets
        if len(all_credentials) > 10000:
            print("   🚀 Using optimized deduplication for large dataset...")
            unique_credentials, stats = self.deduplication.smart_deduplicate_optimized(all_credentials)
        else:
            unique_credentials, stats = self.deduplication.smart_deduplicate(all_credentials)
        
        # Prepare merge report
        merge_report = {
            'files_merged': len(file_paths),
            'total_credentials_before': len(all_credentials),
            'total_credentials_after': len(unique_credentials),
            'duplicates_removed': len(all_credentials) - len(unique_credentials),
            'merge_strategy': strategy,
            'source_files': [os.path.basename(f) for f in file_paths],
            'merge_timestamp': time.time()
        }
        
        # Record in history
        self.merge_history.append(merge_report)
        
        return unique_credentials, merge_report
    
    def get_merge_history(self) -> List[Dict]:
        """Get history of all merge operations"""
        return self.merge_history.copy()

# Existing CorporateEmailDetector class remains unchanged
class CorporateEmailDetector:
    """Advanced corporate email detection and analysis"""
    
    def __init__(self):
        # Common personal email domains
        self.personal_domains = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'icloud.com', 'protonmail.com', 'mail.com', 'yandex.com', 'live.com',
            'msn.com', 'gmx.com', 'zoho.com', 'tutanota.com', 'fastmail.com',
            'hushmail.com', 'lavabit.com', 'keemail.me', 'rocketmail.com'
        }
        
        # Common email patterns for executives
        self.executive_patterns = [
            r'^(ceo|cto|cfo|coo|cio|cmoo|president|vp|director|head|manager|lead)',
            r'.*(executive|chief|officer|director|manager|head|lead)',
            r'^(admin|administrator|office|info|contact|support|help)'
        ]
        
        # Common corporate naming conventions
        self.corporate_patterns = [
            r'\.(com|org|net|edu|gov|mil|io|ai|co|inc|llc|corp|group)$',
            r'[a-zA-Z0-9-]+\.(com|org|net|edu|gov|mil)$'
        ]
    
    def is_corporate_email(self, email):
        """Determine if an email is corporate based on domain analysis"""
        if not email or '@' not in email:
            return False
        
        domain = email.split('@')[1].lower()
        
        # Check if domain is in personal domains
        if domain in self.personal_domains:
            return False
        
        # Check for common corporate TLDs and patterns
        for pattern in self.corporate_patterns:
            if re.search(pattern, domain):
                return True
        
        # If it's not personal and looks like a real domain, consider it corporate
        if '.' in domain and len(domain) > 3 and not any(x in domain for x in ['-', '_']):
            return True
        
        return False
    
    def is_executive_email(self, email, username):
        """Identify potential executive email addresses"""
        username_lower = username.lower()
        
        # Check for executive title patterns in username
        for pattern in self.executive_patterns:
            if re.search(pattern, username_lower):
                return True
        
        # Common executive naming conventions
        executive_indicators = [
            re.match(r'^[a-z]+\.[a-z]+$', username_lower),  # first.last
            re.match(r'^[a-z][a-z]+\.[a-z]+$', username_lower),  # first.last
            re.match(r'^[a-z]+\.[a-z]+[0-9]*$', username_lower),  # first.last123
        ]
        
        return any(executive_indicators)
    
    def analyze_corporate_emails(self, credentials):
        """Comprehensive analysis of corporate credentials"""
        analysis = {
            'total_corporate': 0,
            'total_personal': 0,
            'executive_emails': [],
            'by_domain': defaultdict(int),
            'high_value_domains': [],
            'risk_assessment': {}
        }
        
        for credential in credentials:
            email, password = credential.split(':', 1)
            username = email.split('@')[0]
            domain = email.split('@')[1]
            
            if self.is_corporate_email(email):
                analysis['total_corporate'] += 1
                analysis['by_domain'][domain] += 1
                
                # Check for executive emails
                if self.is_executive_email(email, username):
                    analysis['executive_emails'].append(credential)
            
            else:
                analysis['total_personal'] += 1
        
        # Identify high-value domains (companies with many credentials)
        analysis['high_value_domains'] = sorted(
            analysis['by_domain'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]  # Top 10
        
        # Risk assessment
        total_creds = analysis['total_corporate'] + analysis['total_personal']
        if total_creds > 0:
            corporate_ratio = analysis['total_corporate'] / total_creds
            analysis['risk_assessment'] = {
                'corporate_ratio': corporate_ratio,
                'risk_level': 'HIGH' if corporate_ratio > 0.3 else 'MEDIUM' if corporate_ratio > 0.1 else 'LOW',
                'executive_count': len(analysis['executive_emails']),
                'executive_risk': 'CRITICAL' if len(analysis['executive_emails']) > 0 else 'LOW'
            }
        
        return analysis

# Enhanced UltimateCredentialExtractor with Smart Deduplication
class UltimateCredentialExtractor:
    def __init__(self):
        self.keywords = ['microsoft', 'paypal', 'amazon', 'netflix', 'spotify', 'google']
        self.extraction_history = []
        self.corporate_detector = CorporateEmailDetector()
        
        # NEW: Initialize deduplication and merge systems
        self.deduplication_engine = SmartDeduplication()
        self.merge_manager = MergeManager(self.deduplication_engine)
        
        self.setup_logging()
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('extractor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        banner = """
╔════════════════════════════════════════════════════════════════╗
║                 ULTIMATE CREDENTIAL EXTRACTOR                 ║
║                    DEFENSIVE RESEARCH TOOL                    ║
╚════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def main_menu(self):
        while True:
            self.clear_screen()
            self.display_banner()
            print("1. Process single file")
            print("2. Process DATA folder (multiple files)")
            print("3. Manage keywords")
            print("4. View extraction history")
            print("5. Corporate email analysis")
            print("6. Export configuration")
            print("7. Smart Deduplication & Merging")  # NEW MENU OPTION
            print("8. Exit program")
            print("\n" + "="*60)
            
            choice = input("Select option: ").strip()
            
            if choice == '1':
                self.extraction_menu()
            elif choice == '2':
                self.folder_extraction_menu()
            elif choice == '3':
                self.keyword_management_menu()
            elif choice == '4':
                self.view_history()
            elif choice == '5':
                self.corporate_analysis_menu()
            elif choice == '6':
                self.export_config()
            elif choice == '7':  # NEW: Smart Deduplication menu
                self.deduplication_menu()
            elif choice == '8':
                print("Exiting... Stay secure!")
                break
            else:
                input("Invalid option! Press Enter to continue...")
    
    # NEW: Smart Deduplication & Merging Menu
    def deduplication_menu(self):
        """Smart Deduplication & Merging main menu"""
        while True:
            self.clear_screen()
            self.display_banner()
            print("🔄 SMART DEDUPLICATION & MERGING")
            print("1. Deduplicate existing results")
            print("2. Merge multiple extraction sessions")
            print("3. Merge credential files directly")
            print("4. Configure deduplication settings")
            print("5. View merge statistics & history")
            print("6. Return to main menu")
            print("\n" + "="*60)
            
            choice = input("Select option: ").strip()
            
            if choice == '1':
                self.deduplicate_existing_results()
            elif choice == '2':
                self.merge_sessions_menu()
            elif choice == '3':
                self.merge_files_menu()
            elif choice == '4':
                self.configure_deduplication()
            elif choice == '5':
                self.view_merge_history()
            elif choice == '6':
                break
            else:
                input("Invalid option! Press Enter to continue...")
    
    def deduplicate_existing_results(self):
        """Deduplicate existing extraction result files - OPTIMIZED"""
        self.clear_screen()
        self.display_banner()
        print("🔍 DEDUPLICATE EXISTING RESULTS")
        print("="*60)
        
        # Find all extracted files
        extracted_files = glob.glob("*_extracted_*.txt") + glob.glob("*_Batch_Extracted_*.txt")
        
        if not extracted_files:
            print("❌ No extraction result files found!")
            input("Press Enter to continue...")
            return
        
        print(f"Found {len(extracted_files)} extraction result files:")
        for i, file_path in enumerate(extracted_files, 1):
            file_size = os.path.getsize(file_path)
            print(f"  {i}. {os.path.basename(file_path)} ({file_size:,} bytes)")
        
        # File selection
        selection = input("\nEnter file numbers to process (comma-separated, or 'all'): ").strip()
        
        if selection.lower() == 'all':
            selected_files = extracted_files
        else:
            try:
                indices = [int(x.strip()) - 1 for x in selection.split(',')]
                selected_files = [extracted_files[i] for i in indices if 0 <= i < len(extracted_files)]
            except (ValueError, IndexError):
                print("❌ Invalid selection!")
                input("Press Enter to continue...")
                return
        
        if not selected_files:
            print("❌ No files selected!")
            input("Press Enter to continue...")
            return
        
        # Strategy selection
        print("\n🎯 SELECT MERGE STRATEGY:")
        print("1. Keep newest credentials (default)")
        print("2. Keep oldest credentials")
        print("3. Keep strongest passwords")
        print("4. Keep all (only remove exact duplicates)")
        
        strategy_choice = input("Select strategy (1-4): ").strip() or "1"
        strategy_map = {'1': 'keep_newest', '2': 'keep_oldest', '3': 'keep_strongest', '4': 'keep_all'}
        strategy = strategy_map.get(strategy_choice, 'keep_newest')
        
        # Load and merge files
        all_credentials = []
        total_size = 0
        
        print("\n📥 Loading files...")
        load_progress = ProgressBar(len(selected_files), "Loading files")
        
        for file_path in selected_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    file_lines = []
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            file_lines.append(line)
                    all_credentials.extend(file_lines)
                    total_size += len(file_lines)
                print(f"   ✅ Loaded {os.path.basename(file_path)}: {len(file_lines):,} credentials")
            except Exception as e:
                print(f"❌ Error reading {file_path}: {e}")
            load_progress.update(1)
        
        load_progress.close()
        
        if not all_credentials:
            print("❌ No credentials found in selected files!")
            input("Press Enter to continue...")
            return
        
        print(f"\n📊 Starting with {len(all_credentials):,} total credentials")
        
        # Apply deduplication with optimized method for large datasets
        self.deduplication_engine.set_merge_strategy(strategy)
        if len(all_credentials) > 10000:
            print("   🚀 Using optimized deduplication for large dataset...")
            unique_credentials, stats = self.deduplication_engine.smart_deduplicate_optimized(all_credentials)
        else:
            unique_credentials, stats = self.deduplication_engine.smart_deduplicate(all_credentials)
        
        # Save results
        timestamp = int(time.time())
        output_file = f"Deduplicated_Results_{timestamp}.txt"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("# SMART DEDUPLICATION RESULTS\n")
                f.write(f"# Generated: {time.ctime()}\n")
                f.write(f"# Input files: {len(selected_files)}\n")
                f.write(f"# Strategy: {strategy}\n")
                f.write(f"# Before: {stats['total_processed']:,} credentials\n")
                f.write(f"# After: {stats['final_unique_count']:,} credentials\n")
                f.write(f"# Duplicates removed: {stats['total_processed'] - stats['final_unique_count']:,}\n")
                f.write("# FOR AUTHORIZED RESEARCH ONLY\n\n")
                
                for credential in unique_credentials:
                    f.write(f"{credential}\n")
            
            print(f"\n✅ Deduplication completed!")
            print(f"📊 STATISTICS:")
            print(f"   Input credentials: {stats['total_processed']:,}")
            print(f"   Output credentials: {stats['final_unique_count']:,}")
            print(f"   Duplicates removed: {stats['total_processed'] - stats['final_unique_count']:,}")
            print(f"   Exact duplicates: {stats['exact_duplicates_removed']:,}")
            print(f"   Email conflicts resolved: {stats['email_duplicates_resolved']:,}")
            if stats['fuzzy_matches_found'] > 0:
                print(f"   Fuzzy matches: {stats['fuzzy_matches_found']:,}")
            print(f"💾 Results saved to: {output_file}")
            
        except Exception as e:
            print(f"❌ Error saving results: {e}")
        
        input("\nPress Enter to continue...")
    
    def merge_sessions_menu(self):
        """Merge multiple extraction sessions"""
        self.clear_screen()
        self.display_banner()
        print("🔄 MERGE EXTRACTION SESSIONS")
        print("="*60)
        
        if not self.extraction_history:
            print("❌ No extraction history available!")
            input("Press Enter to continue...")
            return
        
        print("Available sessions:")
        for i, session in enumerate(reversed(self.extraction_history), 1):
            session_id = f"session_{int(session['timestamp'])}"
            print(f"  {i}. {session_id} - {session['type']} - {session['total_credentials']} creds")
        
        selection = input("\nEnter session numbers to merge (comma-separated): ").strip()
        
        try:
            indices = [int(x.strip()) - 1 for x in selection.split(',')]
            reversed_history = list(reversed(self.extraction_history))
            selected_sessions = [reversed_history[i] for i in indices if 0 <= i < len(reversed_history)]
        except (ValueError, IndexError):
            print("❌ Invalid selection!")
            input("Press Enter to continue...")
            return
        
        if not selected_sessions:
            print("❌ No sessions selected!")
            input("Press Enter to continue...")
            return
        
        # Strategy selection
        print("\n🎯 SELECT MERGE STRATEGY:")
        print("1. Keep newest credentials (default)")
        print("2. Keep oldest credentials")
        print("3. Keep strongest passwords")
        
        strategy_choice = input("Select strategy (1-3): ").strip() or "1"
        strategy_map = {'1': 'keep_newest', '2': 'keep_oldest', '3': 'keep_strongest'}
        strategy = strategy_map.get(strategy_choice, 'keep_newest')
        
        # Perform merge
        merged_credentials, merge_report = self.merge_manager.merge_sessions(selected_sessions, strategy)
        
        # Save results
        timestamp = int(time.time())
        output_file = f"Merged_Sessions_{timestamp}.txt"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("# SESSION MERGE RESULTS\n")
                f.write(f"# Generated: {time.ctime()}\n")
                f.write(f"# Sessions merged: {merge_report['sessions_merged']}\n")
                f.write(f"# Strategy: {merge_report['merge_strategy']}\n")
                f.write(f"# Before: {merge_report['total_credentials_before']:,} credentials\n")
                f.write(f"# After: {merge_report['total_credentials_after']:,} credentials\n")
                f.write(f"# Duplicates removed: {merge_report['duplicates_removed']:,}\n")
                f.write("# FOR AUTHORIZED RESEARCH ONLY\n\n")
                
                for credential in merged_credentials:
                    f.write(f"{credential}\n")
            
            print(f"\n✅ Session merge completed!")
            print(f"📊 STATISTICS:")
            print(f"   Sessions merged: {merge_report['sessions_merged']}")
            print(f"   Input credentials: {merge_report['total_credentials_before']:,}")
            print(f"   Output credentials: {merge_report['total_credentials_after']:,}")
            print(f"   Duplicates removed: {merge_report['duplicates_removed']:,}")
            print(f"💾 Results saved to: {output_file}")
            
        except Exception as e:
            print(f"❌ Error saving results: {e}")
        
        input("\nPress Enter to continue...")
    
    def merge_files_menu(self):
        """Merge multiple credential files directly"""
        self.clear_screen()
        self.display_banner()
        print("🔄 MERGE CREDENTIAL FILES")
        print("="*60)
        
        # File discovery
        file_patterns = ['*.txt', '*.log', '*.csv']
        discovered_files = []
        
        for pattern in file_patterns:
            discovered_files.extend(glob.glob(pattern))
        
        if not discovered_files:
            print("❌ No credential files found in current directory!")
            input("Press Enter to continue...")
            return
        
        print("Available files:")
        for i, file_path in enumerate(discovered_files, 1):
            file_size = os.path.getsize(file_path)
            print(f"  {i}. {file_path} ({file_size:,} bytes)")
        
        # File selection
        selection = input("\nEnter file numbers to merge (comma-separated, or 'all'): ").strip()
        
        if selection.lower() == 'all':
            selected_files = discovered_files
        else:
            try:
                indices = [int(x.strip()) - 1 for x in selection.split(',')]
                selected_files = [discovered_files[i] for i in indices if 0 <= i < len(discovered_files)]
            except (ValueError, IndexError):
                print("❌ Invalid selection!")
                input("Press Enter to continue...")
                return
        
        if not selected_files:
            print("❌ No files selected!")
            input("Press Enter to continue...")
            return
        
        # Strategy selection
        print("\n🎯 SELECT MERGE STRATEGY:")
        print("1. Keep newest credentials (default)")
        print("2. Keep oldest credentials")
        print("3. Keep strongest passwords")
        
        strategy_choice = input("Select strategy (1-3): ").strip() or "1"
        strategy_map = {'1': 'keep_newest', '2': 'keep_oldest', '3': 'keep_strongest'}
        strategy = strategy_map.get(strategy_choice, 'keep_newest')
        
        # Perform merge
        merged_credentials, merge_report = self.merge_manager.merge_files(selected_files, strategy)
        
        # Save results
        timestamp = int(time.time())
        output_file = f"Merged_Files_{timestamp}.txt"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("# FILE MERGE RESULTS\n")
                f.write(f"# Generated: {time.ctime()}\n")
                f.write(f"# Files merged: {merge_report['files_merged']}\n")
                f.write(f"# Strategy: {merge_report['merge_strategy']}\n")
                f.write(f"# Before: {merge_report['total_credentials_before']:,} credentials\n")
                f.write(f"# After: {merge_report['total_credentials_after']:,} credentials\n")
                f.write(f"# Duplicates removed: {merge_report['duplicates_removed']:,}\n")
                f.write("# FOR AUTHORIZED RESEARCH ONLY\n\n")
                
                for credential in merged_credentials:
                    f.write(f"{credential}\n")
            
            print(f"\n✅ File merge completed!")
            print(f"📊 STATISTICS:")
            print(f"   Files merged: {merge_report['files_merged']}")
            print(f"   Input credentials: {merge_report['total_credentials_before']:,}")
            print(f"   Output credentials: {merge_report['total_credentials_after']:,}")
            print(f"   Duplicates removed: {merge_report['duplicates_removed']:,}")
            print(f"💾 Results saved to: {output_file}")
            
        except Exception as e:
            print(f"❌ Error saving results: {e}")
        
        input("\nPress Enter to continue...")
    
    def configure_deduplication(self):
        """Configure deduplication settings"""
        self.clear_screen()
        self.display_banner()
        print("⚙️  DEDUPLICATION CONFIGURATION")
        print("="*60)
        
        current_strategies = self.deduplication_engine.strategies
        current_merge_strategy = self.deduplication_engine.merge_strategy
        
        print("Current Configuration:")
        print(f"  Merge Strategy: {current_merge_strategy}")
        print("  Deduplication Methods:")
        for method, enabled in current_strategies.items():
            status = "✅ ENABLED" if enabled else "❌ DISABLED"
            print(f"    {method.replace('_', ' ').title()}: {status}")
        
        print("\n1. Change merge strategy")
        print("2. Toggle deduplication methods")
        print("3. Reset to defaults")
        print("4. Return to previous menu")
        
        choice = input("\nSelect option: ").strip()
        
        if choice == '1':
            self.configure_merge_strategy()
        elif choice == '2':
            self.toggle_deduplication_methods()
        elif choice == '3':
            self.deduplication_engine = SmartDeduplication()
            print("✅ Configuration reset to defaults!")
            input("Press Enter to continue...")
        elif choice == '4':
            return
        else:
            print("❌ Invalid option!")
            input("Press Enter to continue...")
    
    def configure_merge_strategy(self):
        """Configure the merge strategy"""
        self.clear_screen()
        print("🎯 CONFIGURE MERGE STRATEGY")
        print("="*40)
        
        current = self.deduplication_engine.merge_strategy
        print(f"Current strategy: {current}")
        
        print("\nAvailable strategies:")
        strategies = [
            ("keep_newest", "Keep most recently found credentials"),
            ("keep_oldest", "Keep first encountered credentials"),
            ("keep_strongest", "Keep passwords with highest strength"),
            ("keep_all", "Keep all (only remove exact duplicates)")
        ]
        
        for i, (strategy, description) in enumerate(strategies, 1):
            current_indicator = " ← CURRENT" if strategy == current else ""
            print(f"  {i}. {strategy}: {description}{current_indicator}")
        
        try:
            choice = int(input("\nSelect strategy (1-4): ").strip())
            if 1 <= choice <= 4:
                selected_strategy = strategies[choice-1][0]
                self.deduplication_engine.set_merge_strategy(selected_strategy)
                print(f"✅ Merge strategy set to: {selected_strategy}")
            else:
                print("❌ Invalid selection!")
        except ValueError:
            print("❌ Please enter a valid number!")
        
        input("Press Enter to continue...")
    
    def toggle_deduplication_methods(self):
        """Toggle individual deduplication methods on/off"""
        self.clear_screen()
        print("🔧 TOGGLE DEDUPLICATION METHODS")
        print("="*50)
        
        strategies = self.deduplication_engine.strategies
        
        print("Current status:")
        for i, (method, enabled) in enumerate(strategies.items(), 1):
            status = "✅ ENABLED" if enabled else "❌ DISABLED"
            print(f"  {i}. {method.replace('_', ' ').title()}: {status}")
        
        print("\nEnter method numbers to toggle (comma-separated):")
        try:
            selection = input("Selection: ").strip()
            if selection:
                indices = [int(x.strip()) - 1 for x in selection.split(',')]
                methods = list(strategies.keys())
                
                for idx in indices:
                    if 0 <= idx < len(methods):
                        method = methods[idx]
                        strategies[method] = not strategies[method]
                        new_status = "ENABLED" if strategies[method] else "DISABLED"
                        print(f"✅ {method.replace('_', ' ').title()}: {new_status}")
                    else:
                        print(f"⚠️  Invalid index: {idx+1}")
            
            self.deduplication_engine.set_strategy(strategies)
            
        except ValueError:
            print("❌ Invalid input!")
        
        input("Press Enter to continue...")
    
    def view_merge_history(self):
        """View merge operations history and statistics"""
        self.clear_screen()
        self.display_banner()
        print("📊 MERGE HISTORY & STATISTICS")
        print("="*60)
        
        merge_history = self.merge_manager.get_merge_history()
        
        if not merge_history:
            print("No merge operations recorded yet.")
            input("Press Enter to continue...")
            return
        
        print(f"Total merge operations: {len(merge_history)}\n")
        
        for i, merge_op in enumerate(reversed(merge_history), 1):
            print(f"--- Merge Operation {i} ---")
            print(f"Time: {time.ctime(merge_op['merge_timestamp'])}")
            
            if 'sessions_merged' in merge_op:
                print(f"Type: Session Merge")
                print(f"Sessions: {merge_op['sessions_merged']}")
            else:
                print(f"Type: File Merge")
                print(f"Files: {merge_op['files_merged']}")
            
            print(f"Strategy: {merge_op['merge_strategy']}")
            print(f"Before: {merge_op['total_credentials_before']:,} credentials")
            print(f"After: {merge_op['total_credentials_after']:,} credentials")
            print(f"Duplicates removed: {merge_op['duplicates_removed']:,}")
            print(f"Reduction: {(merge_op['duplicates_removed']/merge_op['total_credentials_before']*100):.1f}%")
            print()
        
        # Overall statistics
        total_before = sum(op['total_credentials_before'] for op in merge_history)
        total_after = sum(op['total_credentials_after'] for op in merge_history)
        total_removed = total_before - total_after
        
        print("OVERALL STATISTICS:")
        print(f"Total credentials processed: {total_before:,}")
        print(f"Total duplicates removed: {total_removed:,}")
        if total_before > 0:
            print(f"Overall reduction: {(total_removed/total_before*100):.1f}%")
        
        input("\nPress Enter to continue...")

    def extraction_menu(self):
        """Single file extraction menu""" 
        self.clear_screen()
        self.display_banner()
        print("🔧 SINGLE FILE PROCESSING MODE")
        print("1. Extract email:pass combinations")
        print("2. Extract user:pass combinations") 
        print("3. Return to main menu")
        
        choice = input("Select extraction mode: ").strip()
        
        if choice == '1':
            self.start_extraction('email_pass')
        elif choice == '2':
            self.start_extraction('user_pass')
        elif choice == '3':
            return
        else:
            print("❌ Invalid selection!")
            input("Press Enter to continue...")
    
    def start_extraction(self, mode):
        """Single file extraction method"""
        # Keyword selection
        selected_keywords = self.select_keywords()
        if selected_keywords is None:
            return
        
        # File path input
        file_path = input("Enter log file path: ").strip()
        if not os.path.exists(file_path):
            print("❌ File not found!")
            input("Press Enter to continue...")
            return
        
        # Start extraction
        print(f"\n🚀 Starting {mode} extraction...")
        self.logger.info(f"Starting extraction: mode={mode}, keywords={selected_keywords}, file={file_path}")
        
        try:
            results = self.process_file(file_path, mode, selected_keywords)
            self.save_per_keyword_results(results, mode, "SINGLE")
            self.record_extraction(mode, selected_keywords, file_path, results)
            
            print(f"\n✅ Extraction completed!")
            self.display_extraction_summary(results)
            
        except Exception as e:
            self.logger.error(f"Extraction failed: {e}")
            print(f"❌ Extraction failed: {e}")
        
        input("\nPress Enter to continue...")
    
    def folder_extraction_menu(self):
        """Folder extraction menu"""
        self.clear_screen()
        self.display_banner()
        print("📁 FOLDER PROCESSING MODE")
        print("1. Extract email:pass combinations")
        print("2. Extract user:pass combinations") 
        print("3. Return to main menu")
        
        choice = input("Select extraction mode: ").strip()
        
        if choice == '1':
            self.start_folder_extraction('email_pass')
        elif choice == '2':
            self.start_folder_extraction('user_pass')
        elif choice == '3':
            return
        else:
            print("❌ Invalid selection!")
            input("Press Enter to continue...")
    
    def start_folder_extraction(self, mode):
        """Enhanced method for processing entire folders"""
        # Keyword selection
        selected_keywords = self.select_keywords()
        if selected_keywords is None:
            return
        
        # Folder path input
        folder_path = input("Enter DATA folder path (default: './DATA'): ").strip()
        if not folder_path:
            folder_path = "DATA"
        
        if not os.path.exists(folder_path):
            print(f"❌ Folder '{folder_path}' not found!")
            input("Press Enter to continue...")
            return
        
        # Discover files in folder
        file_patterns = ['*.txt', '*.log', '*.csv', '*.data']
        discovered_files = []
        
        for pattern in file_patterns:
            discovered_files.extend(glob.glob(os.path.join(folder_path, pattern)))
            discovered_files.extend(glob.glob(os.path.join(folder_path, '**', pattern), recursive=True))
        
        # Remove duplicates and sort
        discovered_files = sorted(list(set(discovered_files)))
        
        if not discovered_files:
            print(f"❌ No files found in '{folder_path}' matching common patterns!")
            input("Press Enter to continue...")
            return
        
        # Display discovered files
        print(f"\n📂 Found {len(discovered_files)} files in '{folder_path}':")
        for i, file_path in enumerate(discovered_files, 1):
            file_size = os.path.getsize(file_path)
            print(f"  {i}. {os.path.basename(file_path)} ({file_size:,} bytes)")
        
        # Confirm processing
        confirm = input(f"\nProcess {len(discovered_files)} files? (y/N): ").strip().lower()
        if confirm != 'y':
            print("❌ Folder processing cancelled.")
            input("Press Enter to continue...")
            return
        
        # Start batch extraction
        print(f"\n🚀 Starting batch {mode} extraction...")
        self.logger.info(f"Starting folder extraction: mode={mode}, keywords={selected_keywords}, folder={folder_path}")
        
        try:
            # Process all files and properly aggregate results
            combined_results, file_stats = self.process_all_files(discovered_files, mode, selected_keywords)
            self.save_aggregated_results(combined_results, mode)
            self.record_folder_extraction(mode, selected_keywords, folder_path, discovered_files, combined_results, file_stats)
            
            print(f"\n✅ Batch extraction completed!")
            self.display_folder_extraction_summary(combined_results, file_stats)
            
        except Exception as e:
            self.logger.error(f"Folder extraction failed: {e}")
            print(f"❌ Folder extraction failed: {e}")
        
        input("\nPress Enter to continue...")
    
    def process_all_files(self, file_paths, mode, keywords):
        """Process multiple files and properly aggregate results from ALL files"""
        total_files = len(file_paths)
        combined_results = defaultdict(list)  # This will accumulate ALL credentials
        file_stats = {}
        
        print(f"\n📊 Processing {total_files} files...")
        
        # Create overall progress for files
        file_progress = ProgressBar(total_files, "Files processed")
        
        for i, file_path in enumerate(file_paths, 1):
            try:
                file_name = os.path.basename(file_path)
                print(f"\n📄 Processing file {i}/{total_files}: {file_name}")
                
                # Process individual file
                file_results = self.process_file(file_path, mode, keywords)
                
                # Properly merge results from current file into combined results
                for keyword, credentials in file_results.items():
                    combined_results[keyword].extend(credentials)
                
                # Record file statistics
                total_creds = sum(len(creds) for creds in file_results.values())
                file_stats[file_name] = {
                    'total_credentials': total_creds,
                    'keyword_breakdown': {k: len(v) for k, v in file_results.items() if v},
                    'status': 'SUCCESS'
                }
                
                self.logger.info(f"Processed {file_name}: {total_creds} credentials")
                
            except Exception as e:
                error_msg = f"Error processing {file_path}: {e}"
                self.logger.error(error_msg)
                file_stats[os.path.basename(file_path)] = {
                    'total_credentials': 0,
                    'keyword_breakdown': {},
                    'status': f'ERROR: {str(e)}'
                }
                print(f"❌ {error_msg}")
            
            file_progress.update(1)
        
        file_progress.close()
        return combined_results, file_stats
    
    def process_file(self, file_path, mode, keywords, progress=None):
        """Process a single file and return credentials"""
        total_lines = self.count_lines(file_path)
        if total_lines == 0:
            return defaultdict(list)
        
        # Use provided progress or create local one
        if progress is None:
            print(f"📁 File size: {total_lines:,} lines")
            print("⏳ Processing...")
            progress = ProgressBar(total_lines, "Extracting credentials")
            local_progress = True
        else:
            local_progress = False
        
        results = defaultdict(list)
        results_lock = threading.Lock()
        
        def process_chunk(chunk):
            chunk_results = defaultdict(list)
            for line in chunk:
                if self.is_valid_line(line):
                    extracted = self.extract_credential(line, mode, keywords)
                    for keyword, credential in extracted:
                        chunk_results[keyword].append(credential)
            return chunk_results
        
        def worker(chunk):
            chunk_results = process_chunk(chunk)
            with results_lock:
                for keyword, credentials in chunk_results.items():
                    results[keyword].extend(credentials)
            progress.update(len(chunk))
        
        # Read file in chunks and process with thread pool
        chunk_size = 10000
        chunks = []
        current_chunk = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    current_chunk.append(line.strip())
                    if len(current_chunk) >= chunk_size:
                        chunks.append(current_chunk)
                        current_chunk = []
                if current_chunk:
                    chunks.append(current_chunk)
            
            # Process chunks with thread pool
            with ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 4)) as executor:
                futures = [executor.submit(worker, chunk) for chunk in chunks]
                for future in as_completed(futures):
                    future.result()
            
        except Exception as e:
            self.logger.error(f"Error processing file {file_path}: {e}")
            raise
        
        if local_progress:
            progress.close()
        
        return results

    # UPDATED: Flexible credential extraction for ANY stealer log format
    def extract_credential(self, line, mode, keywords):
        """FIXED: Flexible credential extraction that handles ANY URL format and finds email:password anywhere in line"""
        results = []
        try:
            line = line.strip()
            
            # Check for keyword matches first - this is our primary filter
            line_lower = line.lower()
            matching_keywords = [k for k in keywords if k.lower() in line_lower]
            
            if not matching_keywords:
                return results
            
            # NEW: Much more flexible patterns that handle ANY URL format
            # These patterns look for email:password pairs ANYWHERE in the line
            credential_patterns = [
                # Pattern 1: Standard email:password anywhere in line
                r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):([^:\s\n\r]+)$',
                
                # Pattern 2: Email:password preceded by any URL format (www., https://, domain.com, etc.)
                r'[^:]*[:/]([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):([^:\s\n\r]+)$',
                
                # Pattern 3: Email:password after any path or subdomain
                r'[^:]*\.[^:]*[:/]([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):([^:\s\n\r]+)$',
                
                # Pattern 4: Direct email:password extraction (most flexible - catches anything)
                r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):([^\s\n\r]+)$',
                
                # Pattern 5: Handle complex paths with email:password at end
                r'.*[:/]([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):([^\s\n\r]+)$',
                
                # Pattern 6: Ultra-flexible - find email:password anywhere, password until line end
                r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):([^\n\r]+)$'
            ]
            
            credential_found = None
            
            # Try all patterns until we find a valid credential
            for pattern in credential_patterns:
                match = re.search(pattern, line)
                if match:
                    email, password = match.groups()
                    
                    # Clean up the password (remove any trailing colons or invalid chars)
                    password = password.strip()
                    if password.endswith(':') or password.endswith('/'):
                        password = password.rstrip(':/')
                    
                    # Validate the extracted credential
                    if self.is_valid_credential(email, password, mode):
                        credential_found = f"{email}:{password}"
                        break  # Stop at first valid match
            
            # NEW: If no pattern matched but we have keywords, try brute force extraction
            if not credential_found and matching_keywords:
                credential_found = self._brute_force_extraction(line, mode)
            
            # FIXED: Only add if we found a valid credential
            if credential_found:
                for keyword in matching_keywords:
                    results.append((keyword, credential_found))
            
            return results
            
        except Exception as e:
            self.logger.debug(f"Error processing line: {e}")
            return results

    def _brute_force_extraction(self, line, mode):
        """Brute force method to extract email:password when patterns fail"""
        try:
            # Split by colon and look for email patterns
            parts = line.split(':')
            
            for i, part in enumerate(parts):
                # Check if this part looks like an email
                if self.is_valid_email(part.strip()):
                    # The next part should be the password (or contain it)
                    if i + 1 < len(parts):
                        password_candidate = parts[i + 1]
                        
                        # Password might have more colons, so take until end or next separator
                        if '/' in password_candidate:
                            password_candidate = password_candidate.split('/')[0]
                        if ' ' in password_candidate:
                            password_candidate = password_candidate.split(' ')[0]
                        if '\t' in password_candidate:
                            password_candidate = password_candidate.split('\t')[0]
                        
                        password_candidate = password_candidate.strip()
                        
                        if self.is_valid_credential(part.strip(), password_candidate, mode):
                            return f"{part.strip()}:{password_candidate}"
            
            # If that didn't work, try regex to find email and take everything after as password
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            email_match = re.search(email_pattern, line)
            
            if email_match:
                email = email_match.group()
                email_start = email_match.start()
                
                # Find the colon after the email
                colon_after_email = line.find(':', email_start)
                if colon_after_email != -1:
                    # Extract everything after the colon as password
                    password_candidate = line[colon_after_email + 1:].strip()
                    
                    # Clean up password (remove any path segments, etc.)
                    if '/' in password_candidate:
                        password_candidate = password_candidate.split('/')[0]
                    if ' ' in password_candidate:
                        password_candidate = password_candidate.split(' ')[0]
                    
                    if self.is_valid_credential(email, password_candidate, mode):
                        return f"{email}:{password_candidate}"
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Brute force extraction failed: {e}")
            return None

    def is_valid_credential(self, email, password, mode):
        """Enhanced credential validation - more permissive for stealer logs"""
        if not email or not password:
            return False
        
        # Basic email validation
        if mode == 'email_pass' and not self.is_valid_email(email):
            return False
        
        # Password validation - more permissive for stealer logs
        password = password.strip()
        if len(password) < 1:  # Even single character passwords exist
            return False
        
        # Remove common invalid patterns but be more accepting
        invalid_patterns = [
            r'^\s*$',  # Only whitespace
        ]
        
        for pattern in invalid_patterns:
            if re.match(pattern, password):
                return False
        
        return True
    
    def is_valid_email(self, text):
        """Strict email validation"""
        if not text or '@' not in text or '.' not in text:
            return False
        
        # Strict email pattern
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if re.match(email_pattern, text.strip()):
            # Additional check for common email providers
            common_domains = [
                'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
                'aol.com', 'icloud.com', 'protonmail.com', 'mail.com',
                'yandex.com', 'live.com', 'msn.com', 'outlook.de',
                'yahoo.co.uk', 'googlemail.com', 'gmx.de', 'web.de',
                'hotmail.co.uk', 'icloud.com', 'me.com', 'mac.com'
            ]
            
            domain = text.split('@')[1].lower()
            if any(common_domain in domain for common_domain in common_domains):
                return True
            # Also allow country-specific domains and other valid domains
            elif '.' in domain and len(domain) >= 5 and len(domain) <= 255:
                return True
        
        return False
    
    def save_aggregated_results(self, results, mode):
        """Save aggregated results from ALL files into single files per keyword"""
        timestamp = int(time.time())
        
        for keyword, credentials in results.items():
            if credentials:  # Only create file if there are results
                # Create safe filename with BATCH indicator
                safe_keyword = re.sub(r'[^\w\-_\. ]', '_', keyword)
                output_file = f"{safe_keyword}_Batch_Extracted_{timestamp}.txt"
                
                try:
                    with open(output_file, 'w', encoding='utf-8') as f:
                        # Write metadata header
                        f.write(f"# BATCH Credential Extraction Results - {keyword.upper()}\n")
                        f.write(f"# Generated: {time.ctime()}\n")
                        f.write(f"# Total entries: {len(credentials):,}\n")
                        f.write(f"# Format: login:password\n")
                        f.write(f"# Source keyword: {keyword}\n")
                        f.write(f"# Extraction type: BATCH (Multiple Files)\n")
                        f.write("# FOR AUTHORIZED RESEARCH ONLY\n\n")
                        
                        # Remove duplicates while preserving order
                        unique_credentials = []
                        seen = set()
                        for cred in credentials:
                            if cred not in seen:
                                seen.add(cred)
                                unique_credentials.append(cred)
                        
                        # Write unique credentials
                        for credential in unique_credentials:
                            f.write(f"{credential}\n")
                    
                    self.logger.info(f"Saved {len(unique_credentials)} unique {keyword} results to {output_file}")
                    print(f"💾 Saved {len(unique_credentials)} unique {keyword} credentials to {output_file}")
                    
                except Exception as e:
                    self.logger.error(f"Error saving {keyword} results: {e}")
                    print(f"❌ Error saving {keyword} results: {e}")
    
    def save_per_keyword_results(self, results, mode, extraction_type):
        """Save results in separate files for each keyword (for single file extraction)"""
        timestamp = int(time.time())
        
        for keyword, credentials in results.items():
            if credentials:  # Only create file if there are results
                # Create safe filename
                safe_keyword = re.sub(r'[^\w\-_\. ]', '_', keyword)
                output_file = f"{safe_keyword}_extracted_{mode}_{timestamp}.txt"
                
                try:
                    with open(output_file, 'w', encoding='utf-8') as f:
                        # Write metadata header
                        f.write(f"# Credential Extraction Results - {keyword.upper()}\n")
                        f.write(f"# Generated: {time.ctime()}\n")
                        f.write(f"# Total entries: {len(credentials)}\n")
                        f.write(f"# Format: login:password\n")
                        f.write(f"# Source keyword: {keyword}\n")
                        f.write(f"# Extraction type: {extraction_type}\n")
                        f.write("# FOR AUTHORIZED RESEARCH ONLY\n\n")
                        
                        # Write credentials
                        for credential in credentials:
                            f.write(f"{credential}\n")
                    
                    self.logger.info(f"Saved {len(credentials)} {keyword} results to {output_file}")
                    
                except Exception as e:
                    self.logger.error(f"Error saving {keyword} results: {e}")
                    print(f"❌ Error saving {keyword} results: {e}")
    
    def select_keywords(self):
        if not self.keywords:
            print("❌ No keywords available! Please add keywords first.")
            input("Press Enter to continue...")
            return None
        
        print("\n🔍 SELECT KEYWORDS TO USE:")
        print("0. All keywords")
        for i, keyword in enumerate(self.keywords, 1):
            print(f"{i}. {keyword}")
        
        selection = input("Enter comma-separated numbers, or 0 for all: ").strip()
        
        if selection == '0':
            return self.keywords.copy()
        
        try:
            indices = [int(x.strip()) - 1 for x in selection.split(',')]
            selected = [self.keywords[i] for i in indices if 0 <= i < len(self.keywords)]
            return selected if selected else self.keywords.copy()
        except (ValueError, IndexError):
            print("❌ Invalid selection! Using all keywords.")
            return self.keywords.copy()
    
    def count_lines(self, file_path):
        """Count total lines in file efficiently"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except Exception as e:
            self.logger.error(f"Error counting lines: {e}")
            return 0
    
    def is_valid_line(self, line):
        """Validate if line contains URL:LOGIN:PASSWORD format"""
        # More flexible validation - just check if line has content
        return (isinstance(line, str) and len(line.strip()) > 10)  # Minimum reasonable length
    
    def display_extraction_summary(self, results):
        """Display summary of extracted credentials per keyword"""
        print("\n📊 EXTRACTION SUMMARY:")
        print("="*50)
        total_credentials = 0
        
        for keyword, credentials in sorted(results.items()):
            if credentials:
                count = len(credentials)
                total_credentials += count
                print(f"🔸 {keyword.upper():<15}: {count:>6,} credentials")
        
        print("="*50)
        print(f"📈 TOTAL EXTRACTED: {total_credentials:,} credentials")
        
        # Show file creation info
        print("\n💾 OUTPUT FILES:")
        for keyword in results.keys():
            if results[keyword]:
                safe_keyword = re.sub(r'[^\w\-_\. ]', '_', keyword)
                print(f"   📄 {safe_keyword}_extracted_*.txt")
    
    def display_folder_extraction_summary(self, results, file_stats):
        """Enhanced summary for folder processing"""
        total_credentials = sum(len(creds) for creds in results.values())
        successful_files = sum(1 for stats in file_stats.values() if stats['status'] == 'SUCCESS')
        total_files = len(file_stats)
        
        print(f"\n📊 BATCH EXTRACTION SUMMARY:")
        print("="*60)
        print(f"📂 Files Processed: {successful_files}/{total_files} successful")
        print(f"📈 Total Credentials: {total_credentials:,}")
        print("\n🔑 EXTRACTION BY SERVICE:")
        print("-"*40)
        
        for keyword, credentials in sorted(results.items()):
            if credentials:
                count = len(credentials)
                percentage = (count / total_credentials * 100) if total_credentials > 0 else 0
                print(f"🔸 {keyword.upper():<15}: {count:>8,} ({percentage:.1f}%)")
        
        print("\n📋 FILE STATISTICS:")
        print("-"*40)
        for file_name, stats in file_stats.items():
            status_icon = "✅" if stats['status'] == 'SUCCESS' else "❌"
            print(f"{status_icon} {file_name:<30}: {stats['total_credentials']:>6,} creds")
        
        print("="*60)
        
        # Show file creation info
        print("\n💾 BATCH OUTPUT FILES:")
        for keyword in results.keys():
            if results[keyword]:
                safe_keyword = re.sub(r'[^\w\-_\. ]', '_', keyword)
                print(f"   📄 {safe_keyword}_Batch_Extracted_*.txt")
    
    def record_extraction(self, mode, keywords, input_file, results):
        """Record single file extraction session in history"""
        output_files = {}
        for keyword, credentials in results.items():
            if credentials:
                safe_keyword = re.sub(r'[^\w\-_\. ]', '_', keyword)
                output_files[keyword] = f"{safe_keyword}_extracted_{mode}_*.txt"
        
        session = {
            'type': 'single',
            'timestamp': time.time(),
            'mode': mode,
            'keywords': keywords,
            'input_file': input_file,
            'output_files': output_files,
            'extracted_counts': {k: len(v) for k, v in results.items() if v},
            'total_credentials': sum(len(v) for v in results.values())
        }
        self.extraction_history.append(session)
        
        # Keep only last 50 sessions
        if len(self.extraction_history) > 50:
            self.extraction_history = self.extraction_history[-50:]
    
    def record_folder_extraction(self, mode, keywords, folder_path, file_paths, results, file_stats):
        """Record folder extraction session in history"""
        output_files = {}
        for keyword, credentials in results.items():
            if credentials:
                safe_keyword = re.sub(r'[^\w\-_\. ]', '_', keyword)
                output_files[keyword] = f"{safe_keyword}_Batch_Extracted_*.txt"
        
        session = {
            'type': 'folder',
            'timestamp': time.time(),
            'mode': mode,
            'keywords': keywords,
            'folder_path': folder_path,
            'files_processed': len(file_paths),
            'successful_files': sum(1 for stats in file_stats.values() if stats['status'] == 'SUCCESS'),
            'output_files': output_files,
            'extracted_counts': {k: len(v) for k, v in results.items() if v},
            'total_credentials': sum(len(v) for v in results.values()),
            'file_statistics': file_stats
        }
        self.extraction_history.append(session)
        
        # Keep only last 50 sessions
        if len(self.extraction_history) > 50:
            self.extraction_history = self.extraction_history[-50:]
    
    def corporate_analysis_menu(self):
        """Corporate email analysis menu"""
        self.clear_screen()
        self.display_banner()
        print("🏢 CORPORATE EMAIL ANALYSIS")
        print("1. Analyze existing extraction results")
        print("2. Scan folder for corporate credentials")
        print("3. Add custom corporate domains")
        print("4. View corporate domain database")
        print("5. Return to main menu")
        
        choice = input("Select option: ").strip()
        
        if choice == '1':
            self.analyze_existing_results()
        elif choice == '2':
            self.scan_folder_corporate()
        elif choice == '3':
            self.add_corporate_domains()
        elif choice == '4':
            self.view_corporate_database()
        elif choice == '5':
            return
        else:
            print("❌ Invalid selection!")
            input("Press Enter to continue...")
    
    def analyze_existing_results(self):
        """Analyze previously extracted files for corporate emails"""
        print("\n🔍 ANALYZING EXISTING EXTRACTION RESULTS")
        
        # Find all extracted files
        extracted_files = glob.glob("*_extracted_*.txt") + glob.glob("*_Batch_Extracted_*.txt")
        
        if not extracted_files:
            print("❌ No extraction results found!")
            input("Press Enter to continue...")
            return
        
        print(f"Found {len(extracted_files)} extraction result files")
        
        all_corporate_creds = []
        file_analysis = {}
        
        for file_path in extracted_files:
            print(f"\n📄 Analyzing {os.path.basename(file_path)}...")
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    credentials = []
                    for line in f:
                        if line.strip() and not line.startswith('#'):
                            credentials.append(line.strip())
                    
                if credentials:
                    analysis = self.corporate_detector.analyze_corporate_emails(credentials)
                    file_analysis[file_path] = analysis
                    
                    # Collect corporate credentials
                    for cred in credentials:
                        email = cred.split(':')[0]
                        if self.corporate_detector.is_corporate_email(email):
                            all_corporate_creds.append(cred)
                    
                    print(f"   ✅ Corporate: {analysis['total_corporate']}, Personal: {analysis['total_personal']}")
                    
            except Exception as e:
                print(f"   ❌ Error analyzing {file_path}: {e}")
        
        if all_corporate_creds:
            self.save_corporate_analysis(all_corporate_creds, file_analysis)
            self.display_corporate_report(file_analysis)
        else:
            print("\n❌ No corporate emails found in extraction results.")
        
        input("\nPress Enter to continue...")
    
    def scan_folder_corporate(self):
        """Scan a folder specifically for corporate credentials with progress tracking"""
        folder_path = input("Enter folder path to scan for corporate emails: ").strip()
        if not folder_path or not os.path.exists(folder_path):
            print("❌ Folder not found!")
            input("Press Enter to continue...")
            return
        
        # Discover files
        file_patterns = ['*.txt', '*.log', '*.csv']
        discovered_files = []
        
        for pattern in file_patterns:
            discovered_files.extend(glob.glob(os.path.join(folder_path, pattern)))
        
        if not discovered_files:
            print("❌ No files found!")
            input("Press Enter to continue...")
            return
        
        print(f"\n📂 Found {len(discovered_files)} files")
        print("🚀 Starting corporate email scan...")
        
        # Count total lines for progress tracking
        print("\n⏳ Counting total lines in all files...")
        total_lines = 0
        file_sizes = {}
        
        for file_path in discovered_files:
            file_lines = self.count_lines(file_path)
            total_lines += file_lines
            file_sizes[file_path] = file_lines
            print(f"   📄 {os.path.basename(file_path)}: {file_lines:,} lines")
        
        print(f"\n📊 TOTAL: {total_lines:,} lines across {len(discovered_files)} files")
        
        all_corporate_creds = []
        file_analysis = {}
        processed_lines = 0
        
        # Create overall progress bar
        overall_progress = ProgressBar(total_lines, "Overall progress")
        
        for file_path in discovered_files:
            file_name = os.path.basename(file_path)
            file_line_count = file_sizes[file_path]
            
            print(f"\n📄 Processing: {file_name} ({file_line_count:,} lines)")
            
            # Create file-specific progress bar
            file_progress = ProgressBar(file_line_count, f"Scanning {file_name}")
            
            try:
                corporate_in_file = []
                file_corporate_count = 0
                file_personal_count = 0
                
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        processed_lines += 1
                        
                        # Update both progress bars
                        file_progress.update(1)
                        overall_progress.update(1)
                        
                        if self.is_valid_line(line):
                            extracted = self.extract_credential_simple(line)
                            for cred in extracted:
                                email = cred.split(':')[0]
                                if self.corporate_detector.is_corporate_email(email):
                                    corporate_in_file.append(cred)
                                    all_corporate_creds.append(cred)
                                    file_corporate_count += 1
                                else:
                                    file_personal_count += 1
                
                # Close file progress bar
                file_progress.close()
                
                if corporate_in_file:
                    analysis = self.corporate_detector.analyze_corporate_emails(corporate_in_file)
                    file_analysis[file_path] = analysis
                    print(f"   ✅ Found {len(corporate_in_file):,} corporate credentials")
                    print(f"   📊 Corporate/Personal ratio: {file_corporate_count:,}/{file_personal_count:,}")
                else:
                    print(f"   ℹ️  No corporate emails found")
                    
            except Exception as e:
                # Calculate how many lines we need to skip to the end of this file
                remaining_in_file = file_line_count - (processed_lines % file_line_count if processed_lines % file_line_count != 0 else file_line_count)
                overall_progress.update(remaining_in_file)
                file_progress.close()
                
                error_msg = f"Error scanning {file_path}: {e}"
                self.logger.error(error_msg)
                print(f"   ❌ {error_msg}")
        
        # Close overall progress bar
        overall_progress.close()
        
        # Display final statistics
        print(f"\n📈 SCAN COMPLETED:")
        print(f"   📁 Files processed: {len(discovered_files)}")
        print(f"   📄 Total lines scanned: {processed_lines:,}")
        print(f"   🏢 Corporate credentials found: {len(all_corporate_creds):,}")
        
        if all_corporate_creds:
            self.save_corporate_analysis(all_corporate_creds, file_analysis)
            self.display_corporate_report(file_analysis)
        else:
            print("\n❌ No corporate emails found in scanned files.")
        
        input("Press Enter to continue...")
    
    def extract_credential_simple(self, line):
        """Simple credential extraction for corporate scanning"""
        credentials = []
        try:
            # Basic email:password pattern
            pattern = r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):([^:\s\n\r]+)'
            matches = re.findall(pattern, line)
            for email, password in matches:
                credentials.append(f"{email}:{password}")
        except:
            pass
        return credentials
    
    def save_corporate_analysis(self, corporate_creds, file_analysis):
        """Save corporate analysis results"""
        timestamp = int(time.time())
        
        # Save all corporate credentials
        corp_file = f"Corporate_Credentials_Analysis_{timestamp}.txt"
        with open(corp_file, 'w', encoding='utf-8') as f:
            f.write("# CORPORATE CREDENTIALS ANALYSIS - HIGH RISK\n")
            f.write(f"# Generated: {time.ctime()}\n")
            f.write(f"# Total Corporate Credentials: {len(corporate_creds)}\n")
            f.write("# FOR DEFENSIVE SECURITY RESEARCH ONLY\n\n")
            
            # Group by domain
            domains = defaultdict(list)
            for cred in corporate_creds:
                email = cred.split(':')[0]
                domain = email.split('@')[1]
                domains[domain].append(cred)
            
            # Write by domain
            for domain, creds in sorted(domains.items(), key=lambda x: len(x[1]), reverse=True):
                f.write(f"\n# DOMAIN: {domain} ({len(creds)} credentials)\n")
                for cred in creds:
                    f.write(f"{cred}\n")
        
        # Save executive emails separately
        executive_creds = []
        for analysis in file_analysis.values():
            executive_creds.extend(analysis['executive_emails'])
        
        if executive_creds:
            exec_file = f"Executive_Credentials_HIGH_RISK_{timestamp}.txt"
            with open(exec_file, 'w', encoding='utf-8') as f:
                f.write("# EXECUTIVE CREDENTIALS - CRITICAL RISK\n")
                f.write(f"# Generated: {time.ctime()}\n")
                f.write(f"# Total Executive Credentials: {len(executive_creds)}\n")
                f.write("# IMMEDIATE SECURITY RESPONSE REQUIRED\n\n")
                
                for cred in executive_creds:
                    f.write(f"{cred}\n")
            
            print(f"💼 CRITICAL: Saved {len(executive_creds)} executive credentials to {exec_file}")
        
        print(f"🏢 Saved {len(corporate_creds)} corporate credentials to {corp_file}")
        
        # Save analysis report
        report_file = f"Corporate_Analysis_Report_{timestamp}.txt"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(self.generate_corporate_report(file_analysis))
        
        print(f"📊 Saved analysis report to {report_file}")
    
    def display_corporate_report(self, file_analysis):
        """Display corporate analysis report"""
        print("\n" + "="*70)
        print("🏢 CORPORATE CREDENTIALS ANALYSIS REPORT")
        print("="*70)
        
        total_corporate = sum(analysis['total_corporate'] for analysis in file_analysis.values())
        total_personal = sum(analysis['total_personal'] for analysis in file_analysis.values())
        total_executive = sum(len(analysis['executive_emails']) for analysis in file_analysis.values())
        
        print(f"📈 OVERVIEW:")
        print(f"   Total Corporate Credentials: {total_corporate:,}")
        print(f"   Total Personal Credentials:  {total_personal:,}")
        print(f"   Executive Credentials:       {total_executive:,} ⚠️")
        
        if total_corporate + total_personal > 0:
            corporate_ratio = total_corporate / (total_corporate + total_personal)
            print(f"   Corporate Ratio:            {corporate_ratio:.1%}")
        
        # Top domains
        all_domains = defaultdict(int)
        for analysis in file_analysis.values():
            for domain, count in analysis['by_domain'].items():
                all_domains[domain] += count
        
        if all_domains:
            print(f"\n🎯 TOP TARGETED COMPANIES:")
            for domain, count in sorted(all_domains.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"   {domain}: {count:,} credentials")
        
        # Risk assessment
        print(f"\n⚠️  RISK ASSESSMENT:")
        if total_executive > 0:
            print(f"   🚨 CRITICAL RISK: {total_executive} executive accounts compromised")
        if total_corporate > 100:
            print(f"   🔴 HIGH RISK: Large-scale corporate credential theft ({total_corporate} accounts)")
        elif total_corporate > 10:
            print(f"   🟡 MEDIUM RISK: Significant corporate exposure ({total_corporate} accounts)")
        else:
            print(f"   🟢 LOW RISK: Limited corporate exposure ({total_corporate} accounts)")
        
        print("="*70)
    
    def generate_corporate_report(self, file_analysis):
        """Generate detailed corporate report"""
        report = []
        report.append("CORPORATE CREDENTIALS ANALYSIS REPORT")
        report.append("="*50)
        report.append(f"Generated: {time.ctime()}")
        report.append("")
        
        total_corporate = sum(analysis['total_corporate'] for analysis in file_analysis.values())
        total_personal = sum(analysis['total_personal'] for analysis in file_analysis.values())
        total_executive = sum(len(analysis['executive_emails']) for analysis in file_analysis.values())
        
        report.append("EXECUTIVE SUMMARY:")
        report.append(f"  Total Corporate Credentials: {total_corporate}")
        report.append(f"  Total Personal Credentials:  {total_personal}")
        report.append(f"  Executive Credentials:       {total_executive}")
        report.append("")
        
        # Domain analysis
        all_domains = defaultdict(int)
        for analysis in file_analysis.values():
            for domain, count in analysis['by_domain'].items():
                all_domains[domain] += count
        
        if all_domains:
            report.append("TARGETED COMPANIES (Top 20):")
            for domain, count in sorted(all_domains.items(), key=lambda x: x[1], reverse=True)[:20]:
                report.append(f"  {domain}: {count} credentials")
            report.append("")
        
        # File-by-file breakdown
        report.append("DETAILED BREAKDOWN BY FILE:")
        for file_path, analysis in file_analysis.items():
            report.append(f"  {os.path.basename(file_path)}:")
            report.append(f"    Corporate: {analysis['total_corporate']}")
            report.append(f"    Personal:  {analysis['total_personal']}")
            report.append(f"    Executive: {len(analysis['executive_emails'])}")
            report.append("")
        
        report.append("RECOMMENDED ACTIONS:")
        if total_executive > 0:
            report.append("  🚨 IMMEDIATE: Contact affected companies about executive account compromises")
        if total_corporate > 0:
            report.append("  🔴 HIGH PRIORITY: Notify companies about corporate credential exposure")
        report.append("  🟡 MEDIUM: Analyze password patterns for credential stuffing prevention")
        report.append("  🟢 ROUTINE: Update internal threat intelligence databases")
        
        return "\n".join(report)
    
    def add_corporate_domains(self):
        """Allow users to add custom corporate domains"""
        print("\n🎯 ADD CUSTOM CORPORATE DOMAINS")
        print("Enter domains one per line (empty line to finish):")
        
        domains = []
        while True:
            domain = input("Domain: ").strip().lower()
            if not domain:
                break
            if '.' in domain and domain not in self.corporate_detector.personal_domains:
                domains.append(domain)
                print(f"✅ Added: {domain}")
            else:
                print("❌ Invalid domain or personal email domain")
        
        if domains:
            # These would be saved to a config file in a real implementation
            print(f"\n✅ Added {len(domains)} custom corporate domains")
            print("Note: In future versions, these will be saved to configuration.")
        
        input("Press Enter to continue...")
    
    def view_corporate_database(self):
        """View the corporate detection database"""
        self.clear_screen()
        self.display_banner()
        print("🏢 CORPORATE DETECTION DATABASE")
        print("="*60)
        
        print(f"Personal Email Domains: {len(self.corporate_detector.personal_domains)}")
        print("Sample personal domains:")
        for domain in sorted(list(self.corporate_detector.personal_domains))[:10]:
            print(f"  • {domain}")
        
        print(f"\nExecutive Detection Patterns: {len(self.corporate_detector.executive_patterns)}")
        print("Corporate Domain Patterns:")
        for pattern in self.corporate_detector.corporate_patterns:
            print(f"  • {pattern}")
        
        input("\nPress Enter to continue...")
    
    def keyword_management_menu(self):
        while True:
            self.clear_screen()
            self.display_banner()
            print("📋 CURRENT KEYWORDS:")
            for i, keyword in enumerate(self.keywords, 1):
                print(f"{i}. {keyword}")
            
            print("\n" + "="*60)
            print("1. Add new keyword")
            print("2. Remove keyword")
            print("3. Import keywords from file")
            print("4. Export keywords to file")
            print("5. Clear all keywords")
            print("6. Return to main menu")
            
            choice = input("Select option: ").strip()
            
            if choice == '1':
                self.add_keyword()
            elif choice == '2':
                self.remove_keyword()
            elif choice == '3':
                self.import_keywords()
            elif choice == '4':
                self.export_keywords()
            elif choice == '5':
                self.clear_keywords()
            elif choice == '6':
                break
            else:
                input("Invalid option! Press Enter to continue...")
    
    def add_keyword(self):
        keyword = input("Enter new keyword: ").strip()
        if keyword and keyword not in self.keywords:
            self.keywords.append(keyword.lower())
            self.logger.info(f"Added keyword: {keyword}")
            print(f"✅ Keyword '{keyword}' added successfully!")
        else:
            print("❌ Invalid keyword or keyword already exists!")
        input("Press Enter to continue...")
    
    def remove_keyword(self):
        if not self.keywords:
            print("❌ No keywords to remove!")
            input("Press Enter to continue...")
            return
        
        print("Select keyword to remove:")
        for i, keyword in enumerate(self.keywords, 1):
            print(f"{i}. {keyword}")
        
        try:
            choice = int(input("Enter number: ")) - 1
            if 0 <= choice < len(self.keywords):
                removed = self.keywords.pop(choice)
                self.logger.info(f"Removed keyword: {removed}")
                print(f"✅ Keyword '{removed}' removed!")
            else:
                print("❌ Invalid selection!")
        except ValueError:
            print("❌ Please enter a valid number!")
        input("Press Enter to continue...")
    
    def import_keywords(self):
        file_path = input("Enter keywords file path: ").strip()
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                new_keywords = [line.strip().lower() for line in f if line.strip()]
                self.keywords.extend([k for k in new_keywords if k not in self.keywords])
            self.logger.info(f"Imported {len(new_keywords)} keywords from {file_path}")
            print(f"✅ Imported {len(new_keywords)} keywords!")
        except Exception as e:
            print(f"❌ Error importing keywords: {e}")
        input("Press Enter to continue...")
    
    def export_keywords(self):
        file_path = input("Enter output file path: ").strip()
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                for keyword in self.keywords:
                    f.write(f"{keyword}\n")
            self.logger.info(f"Exported {len(self.keywords)} keywords to {file_path}")
            print(f"✅ Exported {len(self.keywords)} keywords!")
        except Exception as e:
            print(f"❌ Error exporting keywords: {e}")
        input("Press Enter to continue...")
    
    def clear_keywords(self):
        confirm = input("Are you sure you want to clear all keywords? (y/N): ").strip().lower()
        if confirm == 'y':
            self.keywords.clear()
            self.logger.info("Cleared all keywords")
            print("✅ All keywords cleared!")
        input("Press Enter to continue...")
    
    def view_history(self):
        self.clear_screen()
        self.display_banner()
        print("📊 EXTRACTION HISTORY")
        print("="*60)
        
        if not self.extraction_history:
            print("No extraction history available.")
        else:
            for i, session in enumerate(reversed(self.extraction_history), 1):
                print(f"\n--- Session {i} ---")
                print(f"Type: {session['type'].upper()} extraction")
                print(f"Time: {time.ctime(session['timestamp'])}")
                print(f"Mode: {session['mode']}")
                print(f"Keywords: {', '.join(session['keywords'])}")
                
                if session['type'] == 'single':
                    print(f"Input: {session['input_file']}")
                else:
                    print(f"Folder: {session['folder_path']}")
                    print(f"Files: {session['successful_files']}/{session['files_processed']} successful")
                
                print("Results:")
                for keyword, count in session['extracted_counts'].items():
                    print(f"  • {keyword}: {count} credentials")
                print(f"Total: {session['total_credentials']} credentials")
        
        input("\nPress Enter to continue...")
    
    def export_config(self):
        config = {
            'keywords': self.keywords,
            'extraction_history_count': len(self.extraction_history),
            'export_time': time.ctime()
        }
        
        file_path = input("Enter config export path (default: extractor_config.json): ").strip()
        if not file_path:
            file_path = "extractor_config.json"
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            print(f"✅ Configuration exported to {file_path}")
        except Exception as e:
            print(f"❌ Error exporting configuration: {e}")
        
        input("Press Enter to continue...")

def main():
    # Security warning
    print("🔒 ULTIMATE CREDENTIAL EXTRACTOR - DEFENSIVE RESEARCH TOOL")
    print("⚠️  WARNING: For authorized security testing and research only!")
    print("⚠️  Use only on systems you own or have explicit permission to test!")
    print("="*60)
    
    confirm = input("Do you agree to use this tool responsibly? (y/N): ").strip().lower()
    if confirm != 'y':
        print("Exiting...")
        return
    
    extractor = UltimateCredentialExtractor()
    extractor.main_menu()

if __name__ == "__main__":
    main()