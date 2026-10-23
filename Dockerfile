# Base image is pinned to an exact patch tag; a maintainer must additionally
# resolve and append the current @sha256 digest suffix. The docker ecosystem
# in .github/dependabot.yml will keep the digest fresh once it is written
# here. See the release docs for the one-time lookup command, roughly:
#     docker buildx imagetools inspect PATH_TO_IMAGE:3.13.1-alpine3.20
#
# Until the digest is pinned, the exact minor+alpine tag below still
# materially narrows the mutable-tag window relative to 3.13-alpine3.20.
FROM public.ecr.aws/docker/library/python:3.13.1-alpine3.20

# cfn-lint itself is already exact-pinned.
RUN pip install --no-cache-dir cfn-lint[full]==1.58.0
# pydot was previously unconstrained, which meant every image rebuild could
# pull a different pydot. Pin to an exact release so the image is
# reproducible for a given tag of this Dockerfile.
RUN pip install --no-cache-dir pydot==3.0.4

ENTRYPOINT ["cfn-lint"]
CMD ["--help"]
