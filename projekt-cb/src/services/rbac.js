// Macierz RBAC: które role mają które uprawnienia (do wyświetlenia na stronie głównej)
const { db } = require('../db/database');

function getRolePermissionMatrix() {
  const roles = db.prepare('SELECT id, name FROM roles ORDER BY id').all();
  const permissions = db.prepare('SELECT id, code, description FROM permissions ORDER BY id').all();
  const pairs = new Set(
    db.prepare('SELECT role_id, permission_id FROM role_permissions').all()
      .map((r) => `${r.role_id}:${r.permission_id}`)
  );
  return {
    roles,
    permissions,
    has: (roleId, permissionId) => pairs.has(`${roleId}:${permissionId}`),
  };
}

module.exports = { getRolePermissionMatrix };