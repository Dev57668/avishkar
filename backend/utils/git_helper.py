"""
Git repository cloning with security controls
"""

import logging
from pathlib import Path
from typing import Optional
import subprocess
import git
from git import Repo

from config import settings

logger = logging.getLogger(__name__)


class GitHelper:
    """Git repository operations with security controls"""

    @staticmethod
    def clone_repository(
        repo_url: str,
        workspace: Path,
        branch: str = "main",
        depth: int = 1,
        timeout: int = 30
    ) -> Path:
        """
        Clone a git repository with security controls

        Args:
            repo_url: Repository URL
            workspace: Destination workspace
            branch: Branch to clone (default: main)
            depth: Clone depth (default: 1 for shallow clone)
            timeout: Timeout in seconds

        Returns:
            Path to cloned repository

        Raises:
            ValueError: If URL is invalid
            RuntimeError: If clone fails
        """
        # Validate URL
        if not GitHelper._is_valid_repo_url(repo_url):
            raise ValueError(f"Invalid repository URL: {repo_url}")

        clone_path = workspace / "repository"

        try:
            logger.info(f"Cloning repository: {repo_url} (branch: {branch}, depth: {depth})")

            # Clone with shallow depth and single branch
            Repo.clone_from(
                url=repo_url,
                to_path=str(clone_path),
                branch=branch,
                depth=depth,
                single_branch=True
            )

            logger.info(f"Successfully cloned to: {clone_path}")
            return clone_path

        except git.GitCommandError as e:
            logger.error(f"Git clone failed: {e}")
            raise RuntimeError(f"Failed to clone repository: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error during clone: {e}")
            raise RuntimeError(f"Clone error: {str(e)}")

    @staticmethod
    def get_commit_sha(repo_path: Path) -> Optional[str]:
        """
        Get current commit SHA

        Args:
            repo_path: Path to git repository

        Returns:
            Commit SHA or None if not a git repo
        """
        try:
            repo = Repo(repo_path)
            return repo.head.commit.hexsha
        except Exception as e:
            logger.warning(f"Could not get commit SHA: {e}")
            return None

    @staticmethod
    def get_branch_name(repo_path: Path) -> Optional[str]:
        """
        Get current branch name

        Args:
            repo_path: Path to git repository

        Returns:
            Branch name or None
        """
        try:
            repo = Repo(repo_path)
            return repo.active_branch.name
        except Exception as e:
            logger.warning(f"Could not get branch name: {e}")
            return None

    @staticmethod
    def _is_valid_repo_url(url: str) -> bool:
        """
        Validate repository URL

        Args:
            url: Repository URL to validate

        Returns:
            True if URL appears valid
        """
        # Basic validation - should start with http/https/git
        valid_prefixes = ('http://', 'https://', 'git@', 'git://')

        if not any(url.startswith(prefix) for prefix in valid_prefixes):
            return False

        # Block file:// protocol
        if url.startswith('file://'):
            logger.warning("file:// protocol blocked for security")
            return False

        # Block localhost/internal IPs (basic check)
        if any(host in url.lower() for host in ['localhost', '127.0.0.1', '0.0.0.0']):
            logger.warning("Local URLs blocked for security")
            return False

        return True


# Global git helper instance
git_helper = GitHelper()
