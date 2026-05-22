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
                # Створюємо тимчасовий askpass скрипт
                askpass_path = os.path.abspath("askpass.sh")
                with open(askpass_path, "w") as f:
                    # Якщо Git просить Username — повертаємо будь-який текст (напр. 'git')
                    # Якщо просить Password — повертаємо сам токен
                    f.write(f'''#!/bin/sh
                case "$1" in
                    *Username*) echo "git" ;;
                    *Password*) echo "{self.github_token}" ;;
                esac
                ''')

                # Робимо скрипт виконуваним
                os.chmod(askpass_path, 0o700)

                # Задаємо змінну оточення для Git
                os.environ["GIT_ASKPASS"] = askpass_path

            repo = Repo.clone_from(self.repo_url, self.local_dir)

            if self.branch:
                repo.heads[self.branch].checkout()
            print(f"Repository {self.repo_url} cloned successfully!")
        except Exception as e:
            print(f"Error cloning repository: {e}")
            raise
