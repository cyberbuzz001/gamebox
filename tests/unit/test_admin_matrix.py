from gamebox.admin.matrix import (
    _classify, AuthorizationMatrix, MatrixRow,
    ACCESS_ALLOWED, AUTHENTICATION_REQUIRED, AUTHORIZATION_REQUIRED, ACCESS_DENIED,
)


def test_classify_status():
    assert _classify(200, '{"ok":true}') == ACCESS_ALLOWED
    assert _classify(200, '{"error":"x"}') == ACCESS_DENIED
    assert _classify(401, "") == AUTHENTICATION_REQUIRED
    assert _classify(403, "") == AUTHORIZATION_REQUIRED


def test_accessible_without_admin():
    rows = [
        MatrixRow("User management", "GET /api/admin/users", ACCESS_ALLOWED,
                  ACCESS_ALLOWED, ACCESS_ALLOWED),
        MatrixRow("Admin settings", "GET /api/admin/settings", AUTHENTICATION_REQUIRED,
                  AUTHORIZATION_REQUIRED, ACCESS_ALLOWED),
    ]
    acc = AuthorizationMatrix.accessible_without_admin(rows)
    assert len(acc) == 1 and acc[0].function == "User management"
