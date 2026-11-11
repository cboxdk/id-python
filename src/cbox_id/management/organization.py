"""The organization plane under its Cbox ID v3 name."""

from __future__ import annotations

from .generated.workspace import WorkspaceClient, WorkspaceMethods
from .transport import ManagementTransport


class OrganizationClient(WorkspaceClient):
    """Cbox ID — the organization plane: the customer's own Cbox account, above every
    environment it owns, with its projects, environments, members and keys.

    Cbox ID calls the account an organization; this SDK called it a workspace. This is
    :class:`WorkspaceClient` under its new name, so code typed against the old name accepts
    it, and every method is the same. ``client.organization`` is ``client.workspace``.

    Takes a ``cbid_org_…`` key (a ``cbid_ws_…`` key keeps working) or a person's root access
    token::

        org = OrganizationClient(api_url="https://api.cboxid.com", api_key="cbid_org_…")
        org.organization.get()
    """

    #: The organization itself (get, settings): the same namespace as ``workspace``.
    organization: WorkspaceMethods

    def _bind(self, core: ManagementTransport) -> None:
        super()._bind(core)
        self.organization = self.workspace
