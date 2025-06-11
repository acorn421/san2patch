from san2patch.utils.cmd import BaseCommander


class DockerHelper(BaseCommander):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_container_id(self, container_name: str):
        return self.run_cmd(
            f'docker ps -qf "name={container_name}"',
            pipe=True,
        ).stdout.strip()

    def pull_benchmark_image(self):
        self.run_cmd(
            "docker pull acorn421/san2patch-benchmark",
            pipe=True,
        )

    def run_benchmark_container(self):
        self.run_cmd(
            "docker run -d --name san2patch-benchmark acorn421/san2patch-benchmark",
            pipe=True,
        )

    def get_benchmark_container_id(self):
        container_id = self.get_container_id("san2patch-benchmark")

        if container_id is None or container_id == "":
            try:
                self.run_benchmark_container()
                container_id = self.get_container_id("san2patch-benchmark")
            except Exception as e:
                self.logger.error(f"Error running benchmark container: {e}")
                raise e

        return container_id
