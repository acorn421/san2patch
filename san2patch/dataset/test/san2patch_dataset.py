import json
import os
import shutil

from san2patch.dataset.base_dataset import BaseDataset
from san2patch.dataset.reproducer.reproducer import San2PatchReproducer
from san2patch.utils.enum import LanguageEnum


class San2PatchDataset(BaseDataset):
    name = "san2patch"
    language = LanguageEnum.C

    def chk_download(self):
        return os.path.exists(os.path.join(self.download_dir, "san2patch-benchmark"))

    def download(self):
        if self.chk_download():
            self.logger.info(
                f"Dataset {self.name} is already downloaded. Skip downloading."
            )
            return

        self.logger.info("Downloading dataset {self.name}")

        self.run_cmd(
            "git clone https://github.com/acorn421/san2patch-benchmark/",
            cwd=self.download_dir,
        )

        self.logger.info("Download completed")

    def extract(self):
        super().extract()

        metadata_file = os.path.join(
            self.download_dir, "san2patch-benchmark", "meta-data.json"
        )

        with open(metadata_file, "r") as f:
            metadata = json.load(f)

        for vuln_data in metadata:
            # Generating San output
            if os.path.exists(
                os.path.join(self.san_dir, f"{vuln_data['bug_id']}.san")
            ) or os.path.exists(
                os.path.join(self.san_raw_dir, f"{vuln_data['bug_id']}.err")
            ):
                self.logger.info(
                    f"Sanitizer output already exists for {vuln_data['bug_id']}. Skip generating."
                )
            else:
                reproducer = San2PatchReproducer(vuln_data)
                reproducer.run()

            # Download patch file
            if os.path.exists(
                os.path.join(self.patch_dir, f"{vuln_data['bug_id']}.diff")
            ):
                self.logger.info(
                    f"Patch file already exists for {vuln_data['bug_id']}. Skip downloading."
                )
            else:
                reproducer = San2PatchReproducer(vuln_data)
                reproducer.setup()

                patch_file = os.path.join(self.patch_dir, f"{vuln_data['bug_id']}.diff")
                # self.run_cmd(f'docker cp {reproducer.container_id}:{reproducer.data_dir}/dev.patch {patch_file}')
                self.run_cmd(
                    f"docker cp {reproducer.container_id}:{reproducer.experiment_dir}/dev-patch/fix.patch {patch_file}"
                )

            # Save vuln_data
            if os.path.exists(
                os.path.join(self.vuln_dir, f"{vuln_data['bug_id']}.json")
            ):
                self.logger.info(
                    f"Vulnerability data already exists for {vuln_data['bug_id']}. Skip saving."
                )
            else:
                vuln_file = os.path.join(self.vuln_dir, f"{vuln_data['bug_id']}.json")

                with open(vuln_file, "w") as f:
                    json.dump(vuln_data, f, indent=4)

        self.run_get_only_san_output()

    def run_get_only_san_output(self):
        for root, _, files in os.walk(self.san_raw_dir):
            for file in files:
                if not file.endswith(".err"):
                    continue

                self.logger.info(f"Retrieving sanitizer output for {file}")

                with open(os.path.join(root, file), "r", errors="ignore") as f:
                    full_txt = f.read()

                san_output = self.get_only_san_output(full_txt)

                if not san_output:
                    self.logger.error(f"Sanitizer output not found for {file}")
                    continue

                with open(
                    os.path.join(self.san_dir, file.split(".")[0] + ".san"), "w"
                ) as f:
                    f.write(san_output)

                self.logger.info(f"Sanitizer output retrieved for {file}")

    def preprocess(self):
        # Just copy the files
        self.setup_directory(self.preprocessed_dir)

        self.logger.info("Preprocessing started")

        for root, _, files in os.walk(os.path.join(self.extracted_dir, "vuln")):
            for file in files:
                if not file.endswith(".json"):
                    continue

                vuln_id = file.split(".")[0]

                with open(os.path.join(root, file), "r") as f:
                    vuln_data = json.load(f)

                try:
                    # Sanitizer output
                    shutil.copyfile(
                        os.path.join(self.extracted_dir, "sanitizer", f"{vuln_id}.san"),
                        os.path.join(self.san_dir, f"{vuln_id}.san"),
                    )

                    # Patch file
                    try:
                        shutil.copyfile(
                            os.path.join(
                                self.extracted_dir, "patch", f"{vuln_id}.diff"
                            ),
                            os.path.join(self.patch_dir, f"{vuln_id}.diff"),
                        )
                    except FileNotFoundError:
                        self.logger.warning(f"Patch file not found for {vuln_id}")

                    # Project Repo
                    reproducer = San2PatchReproducer(vuln_data)
                    reproducer.setup()

                    repo_dir = os.path.join(self.repo_dir, reproducer.project_name)
                    if not os.path.exists(f"{repo_dir}_{vuln_id}"):
                        self.run_cmd(
                            f"docker cp {reproducer.container_id}:{reproducer.experiment_dir}/src {repo_dir}_{vuln_id}"
                        )

                    # Vuln data
                    with open(os.path.join(self.vuln_dir, f"{vuln_id}.json"), "w") as f:
                        json.dump(vuln_data, f, indent=4)

                except FileNotFoundError as e:
                    self.logger.error(f"File not found for {vuln_id}. {e}")
                    continue

        self.logger.info("Preprocessing completed")
