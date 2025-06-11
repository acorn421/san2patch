import click

import san2patch.dataset.test as test_dataset
from san2patch.dataset.base_dataset import BaseDataset
from san2patch.dataset.test.final_dataset import FinalTestDataset


@click.group()
@click.argument("dataset_name")
@click.pass_context
def cli(ctx, dataset_name):
    ctx.ensure_object(dict)

    try:
        dataset_class = getattr(test_dataset, dataset_name + "Dataset")
    except AttributeError:
        raise ValueError(f"Dataset {dataset_name} not found")

    # Create dataset instance
    dataset_instance = dataset_class()

    ctx.obj["dataset_instance"] = dataset_instance


@cli.command()
@click.pass_context
def download(ctx):
    dataset_instance: BaseDataset = ctx.obj["dataset_instance"]
    dataset_instance.download()


@cli.command()
@click.pass_context
def extract(ctx):
    dataset_instance: BaseDataset = ctx.obj["dataset_instance"]
    dataset_instance.extract()


@cli.command()
@click.pass_context
def preprocess(ctx):
    dataset_instance: BaseDataset = ctx.obj["dataset_instance"]
    dataset_instance.preprocess()


@cli.command()
@click.pass_context
def all(ctx):
    dataset_instance: BaseDataset = ctx.obj["dataset_instance"]
    dataset_instance.download()
    dataset_instance.extract()
    dataset_instance.preprocess()


@cli.command()
@click.pass_context
def extract_and_save_patch_commit_id(ctx):
    dataset_instance: BaseDataset = ctx.obj["dataset_instance"]

    dataset_instance.extract_and_save_patch_commit_id()


@cli.command()
@click.pass_context
def download_repo(ctx):
    dataset_instance: BaseDataset = ctx.obj["dataset_instance"]

    dataset_instance.setup_directory(dataset_instance.preprocessed_dir)
    dataset_instance.download_repo()


@cli.command()
@click.pass_context
def aggregate(ctx):
    dataset_instance: FinalTestDataset = ctx.obj["dataset_instance"]

    if dataset_instance.name not in ["final-test"]:
        raise ValueError("Aggregate command can only be run on FinalDataset")

    dataset_instance.aggregate()


if __name__ == "__main__":
    cli()
