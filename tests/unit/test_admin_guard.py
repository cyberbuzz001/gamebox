import pytest
from gamebox.admin.guard import DestructiveTestGuard, GuardBlocked
from gamebox.core.models import RequestClass


def test_get_is_read_safe():
    g = DestructiveTestGuard()
    assert g.is_read_safe("GET", "https://api.test/api/admin/settings")


def test_post_admin_write_not_read_safe():
    g = DestructiveTestGuard()
    assert not g.is_read_safe("POST", "https://api.test/api/admin/wallet/adjust", "{}")
    with pytest.raises(GuardBlocked):
        g.ensure_read_only("POST", "https://api.test/api/admin/wallet/adjust", "{}")


def test_delete_is_destructive():
    g = DestructiveTestGuard()
    assert g.is_destructive("DELETE", "https://api.test/api/admin/users/2")
    assert g.classify("DELETE", "https://api.test/api/admin/users/2") == RequestClass.DESTRUCTIVE
