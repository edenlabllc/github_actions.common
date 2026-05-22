import os

from git import Repo


class GitHubRepoManager:
    def __init__(self, local_dir: str, repo_url: str, branch: str | None = None, github_token: str | None = None):
        self.local_dir = local_dir
        self.repo_url = repo_url
        self.branch = branch
        self.github_token = github_token

    def clone_or_update_repo(self):
        print("Cloning repository...")

        try:
            if self.github_token and len(self.github_token) > 0:
                os.environ["GITHUB_TOKEN"] = self.github_token
                os.environ["GIT_ASKPASS"] = "echo"
                os.environ["GIT_PASSWORD"] = os.environ["GITHUB_TOKEN"]
                print(f"Using GitHub token: {'****' + self.github_token[-4:]}")

            repo = Repo.clone_from(self.repo_url, self.local_dir)

            if self.branch:
                repo.heads[self.branch].checkout()
            print(f"Repository {self.repo_url} cloned successfully!")
        except Exception as e:
            print(f"Error cloning repository: {e}")
            raise
