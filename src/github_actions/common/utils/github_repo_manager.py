from git import Repo


class GitHubRepoManager:
    def __init__(self, local_dir: str, repo_url: str, branch: str | None = None, github_token: str | None = None):
        self.local_dir = local_dir
        self.repo_url = repo_url
        self.branch = branch
        self.github_token = github_token

    def clone_or_update_repo(self):
        print("Cloning repository...")

        env = None
        if self.github_token and len(self.github_token) > 0:
            env = {"GITHUB_TOKEN": self.github_token}

        repo = Repo.clone_from(self.repo_url, self.local_dir, env=env)
        if self.branch:
            repo.heads[self.branch].checkout()
        print(f"Repository {self.repo_url} cloned successfully!")
