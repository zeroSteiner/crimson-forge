import os
from datetime import date

from invoke import task

ECR_REPOSITORY = "public.ecr.aws/n5b4u6h0/zerosteiner/crimson-forge"


@task
def build(ctx, tag="crimson-forge"):
    """Build the container image using podman.

    Args:
        tag: Tag for the container image (default: crimson-forge)
    """
    print(f"Building container image: {tag}")
    ctx.run(f"podman build -t {tag} -f Containerfile .", pty=True)
    print(f"✓ Successfully built {tag}")


@task(pre=[build])
def push(ctx, tag="crimson-forge"):
    """Build and push the container image to ECR with a date-based tag.

    Args:
        tag: Local tag of the container image to push (default: crimson-forge)
    """
    ecr_date_tag = f"{ECR_REPOSITORY}:{date.today().strftime('%Y%m%d')}"
    ecr_latest_tag = f"{ECR_REPOSITORY}:latest"
    for ecr_tag in (ecr_date_tag, ecr_latest_tag):
        print(f"Tagging {tag} as {ecr_tag}")
        ctx.run(f"podman tag {tag} {ecr_tag}")
        print(f"Pushing {ecr_tag}")
        ctx.run(f"podman push {ecr_tag}", pty=True)
    print(f"✓ Successfully pushed {ecr_date_tag} and {ecr_latest_tag}")


@task(pre=[build])
def shell(ctx, tag="crimson-forge"):
    """Build the container image and open a bash shell inside it.

    Args:
        tag: Tag of the container image to run (default: crimson-forge)
    """
    os.execvp("podman", ["podman", "run", "--rm", "-v", f"{os.getcwd()}:/opt/crimson-forge:z", "-ti", tag, "/bin/bash"])

