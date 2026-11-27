"""PromptIntel REST client. Response content is untrusted threat intelligence."""

__version__ = "0.1.0"

from .client import Client, ClientError, Response

__all__ = ["Client", "ClientError", "Response", "__version__"]

