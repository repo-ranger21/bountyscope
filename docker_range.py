import argparse
import random
import shutil
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path


class DockerWordPressRange:
    def __init__(self, plugin_slug, plugin_version=None):
        self.plugin_slug = plugin_slug
        self.plugin_version = plugin_version
        self.temp_dir = Path(tempfile.mkdtemp(prefix="wp_range_"))
        self.compose_file = self.temp_dir / "docker-compose.yml"
        self.wp_port = self._get_random_port()
        self.admin_user = "admin"
        self.admin_pass = "Password123!"
        self.db_name = "wordpress"
        self.db_user = "wpuser"
        self.db_pass = "wppass"
        self.db_root_pass = "rootpass"
        self.project_name = f"wp_{self._random_string(8)}"
        self._write_compose_file()

    def _get_random_port(self):
        import socket
        while True:
            port = random.randint(49152, 65535)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(("127.0.0.1", port)) != 0:
                    return port

    def _random_string(self, length):
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def _write_compose_file(self):
        compose = f"""
version: '3.8'
services:
  db:
    image: mariadb:10.6
    restart: always
    environment:
      MYSQL_DATABASE: {self.db_name}
      MYSQL_USER: {self.db_user}
      MYSQL_PASSWORD: {self.db_pass}
      MYSQL_ROOT_PASSWORD: {self.db_root_pass}
    volumes:
      - db_data:/var/lib/mysql
  wordpress:
    image: wordpress:latest
    restart: always
    depends_on:
      - db
    ports:
      - '{self.wp_port}:80'
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: {self.db_user}
      WORDPRESS_DB_PASSWORD: {self.db_pass}
      WORDPRESS_DB_NAME: {self.db_name}
    volumes:
      - wp_data:/var/www/html
volumes:
  db_data:
  wp_data:
"""
        self.compose_file.write_text(compose)

    def up(self):
        try:
            subprocess.run([
                "docker", "compose", "-f", str(self.compose_file), "-p", self.project_name, "up", "-d"
            ], cwd=self.temp_dir, check=True)
            self._wait_for_db()
            self._wait_for_wordpress()
            self._install_wp_cli()
            self._provision_wordpress()
            self._install_plugin()
            print(f"\n[+] WordPress running at: http://localhost:{self.wp_port}")
            print(f"[+] Admin credentials: {self.admin_user} / {self.admin_pass}\n")
        except Exception as e:
            print(f"[!] Error: {e}", file=sys.stderr)
            self.teardown()
            sys.exit(1)

    def _wait_for_db(self, timeout=120):
        start = time.time()
        while time.time() - start < timeout:
            try:
                subprocess.run([
                    "docker", "compose", "-f", str(self.compose_file), "-p", self.project_name,
                    "exec", "-T", "db", "mysqladmin", "ping", "-h", "localhost", "-uwpuser", f"-p{self.db_pass}"
                ], cwd=self.temp_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return
            except subprocess.CalledProcessError:
                time.sleep(2)
        raise RuntimeError("MariaDB did not become ready in time.")

    def _install_wp_cli(self):
        # Install WP-CLI in the running wordpress container as root
        cmd = [
            "docker", "compose", "-f", str(self.compose_file), "-p", self.project_name,
            "exec", "-T", "wordpress",
            "bash", "-c",
            "curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && chmod +x wp-cli.phar && mv wp-cli.phar /usr/local/bin/wp"
        ]
        subprocess.run(cmd, cwd=self.temp_dir, check=True)

    def _wait_for_wordpress(self, timeout=120):
        import requests
        url = f"http://localhost:{self.wp_port}/wp-login.php"
        start = time.time()
        while time.time() - start < timeout:
            try:
                r = requests.get(url, timeout=3)
                if r.status_code == 200:
                    return
            except Exception:
                pass
            time.sleep(2)
        raise RuntimeError("WordPress did not become ready in time.")

    def _exec_wp(self, args, check=True):
        # Always append --allow-root to every wp command
        cmd = [
            "docker", "compose", "-f", str(self.compose_file), "-p", self.project_name,
            "exec", "-T", "wordpress", "wp"] + args + ["--allow-root"]
        return subprocess.run(cmd, cwd=self.temp_dir, check=check, capture_output=True, text=True)

    def _provision_wordpress(self):
        # Wait for MariaDB to be ready using mysqladmin ping in the db container
        db_container = f"{self.project_name}-db-1"
        for attempt in range(30):
            try:
                subprocess.run([
                    "docker", "exec", db_container,
                    "mysqladmin", "ping", "-h", "localhost", "-uroot", f"-p{self.db_root_pass}", "--silent"
                ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                break
            except subprocess.CalledProcessError:
                if attempt == 29:
                    raise RuntimeError("MariaDB never became available to mysqladmin ping.")
                time.sleep(4)

        # Wait for WordPress entrypoint to generate wp-config.php
        wp_container = f"{self.project_name}-wordpress-1"
        for attempt in range(15):
            try:
                subprocess.run([
                    "docker", "exec", wp_container, "test", "-f", "/var/www/html/wp-config.php"
                ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                break
            except subprocess.CalledProcessError:
                if attempt == 14:
                    raise RuntimeError("wp-config.php was never generated by the WordPress entrypoint.")
                time.sleep(2)

        # Install WP if not already installed, with retry loop
        url = f"http://localhost:{self.wp_port}"
        for attempt in range(10):
            result = self._exec_wp([
                "core", "install",
                f"--url={url}",
                "--title=TestSite",
                f"--admin_user={self.admin_user}",
                f"--admin_password={self.admin_pass}",
                "--admin_email=admin@local.test"
            ], check=False)
            if result.returncode == 0:
                break
            if "WordPress is already installed." in (result.stderr or ""):
                break
            if attempt == 9:
                print("[!] wp core install failed after multiple attempts.")
                print("[WP-CLI STDOUT]\n" + (result.stdout or ""))
                print("[WP-CLI STDERR]\n" + (result.stderr or ""), file=sys.stderr)
                self.teardown()
                sys.exit(1)
            time.sleep(3)

    def _install_plugin(self):
        args = ["plugin", "install", self.plugin_slug]
        if self.plugin_version:
            args.append(f"--version={self.plugin_version}")
        args += ["--force", "--activate"]
        result = self._exec_wp(args, check=False)
        if result.returncode != 0:
            print("[!] Plugin install failed.")
            print("[WP-CLI STDOUT]\n" + (result.stdout or ""))
            print("[WP-CLI STDERR]\n" + (result.stderr or ""), file=sys.stderr)
            self.teardown()
            sys.exit(1)

    @classmethod
    def teardown(cls, temp_dir=None, project_name=None):
        # If called as instance method, use self values
        if hasattr(cls, 'temp_dir') and hasattr(cls, 'project_name'):
            temp_dir = getattr(cls, 'temp_dir')
            project_name = getattr(cls, 'project_name')
        if temp_dir and project_name:
            try:
                subprocess.run([
                    "docker", "compose", "-f", str(Path(temp_dir) / "docker-compose.yml"), "-p", project_name, "down", "-v"
                ], cwd=temp_dir, check=True)
            except Exception:
                pass
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description="Ephemeral local WordPress Docker range for plugin testing.")
    parser.add_argument("plugin_slug", help="WordPress plugin slug (e.g., blog2social)")
    parser.add_argument("--version", help="Plugin version (optional)")
    args = parser.parse_args()
    wp_range = DockerWordPressRange(args.plugin_slug, args.version)
    try:
        wp_range.up()
    except Exception as e:
        print(f"[!] Fatal error: {e}", file=sys.stderr)
        wp_range.teardown()
        sys.exit(1)
    except KeyboardInterrupt:
        print("[!] Interrupted. Cleaning up...")
        wp_range.teardown()
        sys.exit(1)

if __name__ == "__main__":
    main()
