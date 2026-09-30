"""Access regressions; in-memory SQL fixtures and mocked account service only."""
import hashlib
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import sqlglot
import app as workspace
import auth
import db
from policy import ROLE_TABLES, SOURCE_COLUMNS, capabilities, policy_fingerprint


class QueryAccessTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        for source, columns in SOURCE_COLUMNS.items():
            self.db.execute('CREATE TABLE "' + source + '" (' + ','.join('"' + col + '" TEXT' for col in columns) + ')')
        self.db.executescript("""
            INSERT INTO SalesOrders (OrderID,Region,NetAmount) VALUES ('1','South',100),('2','North',900);
            INSERT INTO SalesOrderItems (ItemID,OrderID,LineTotal) VALUES ('1','1',100),('2','2',900);
            INSERT INTO SalesReturns (ReturnID,OrderID,ReturnAmount) VALUES ('1','1',10),('2','2',90);
            INSERT INTO Employees (EmployeeID,DeptID) VALUES ('1','3'),('2','5');
            INSERT INTO Payroll (EmployeeID,NetSalary) VALUES ('1',100),('2',900);
            INSERT INTO Expenses (DeptID,Amount) VALUES ('3',30),('5',50);
        """)

    def tearDown(self):
        self.db.close()

    def run_query(self, sql, role, region=None, dept=3):
        safe, reason, query, _ = workspace._prepare_sql(sql, role, region, dept)
        self.assertTrue(safe, reason)
        query = sqlglot.transpile(query, read='mysql', write='sqlite')[0]
        return self.db.execute(query).fetchall()

    def test_every_role_source_boundary(self):
        for role, allowed in ROLE_TABLES.items():
            for source in list(SOURCE_COLUMNS) + ['AppUsers', 'Roles', 'AuditLog', 'AuthSessions']:
                with self.subTest(role=role, source=source):
                    safe, _, _, _ = workspace._prepare_sql('SELECT COUNT(*) FROM ' + source, role, 'South', 3)
                    self.assertEqual(safe, source in allowed)

    def test_sales_scope_survives_or_and_aggregates(self):
        self.assertEqual(self.run_query("SELECT SUM(NetAmount) FROM SalesOrders WHERE Region = 'North' OR 1=1", 'sales', 'South'), [(100,)])

    def test_sales_child_sources_scoped_without_model_join(self):
        self.assertEqual(self.run_query('SELECT SUM(LineTotal) FROM SalesOrderItems', 'sales', 'South'), [(100,)])
        self.assertEqual(self.run_query('SELECT SUM(ReturnAmount) FROM SalesReturns', 'sales', 'South'), [(10,)])

    def test_outer_join_cannot_leak_unrelated_child_rows(self):
        self.assertEqual(self.run_query('SELECT SUM(i.LineTotal) FROM SalesOrderItems i LEFT JOIN SalesOrders o ON 1=0', 'sales', 'South'), [(100,)])
        self.assertEqual(self.run_query('SELECT SUM(i.LineTotal) FROM SalesOrders o RIGHT JOIN SalesOrderItems i ON 1=0', 'sales', 'South'), [(100,)])

    def test_finance_scope_applies_before_join(self):
        self.assertEqual(self.run_query('SELECT SUM(NetSalary) FROM Payroll', 'finance'), [(100,)])
        self.assertEqual(self.run_query('SELECT SUM(p.NetSalary) FROM Payroll p LEFT JOIN Employees e ON 1=0', 'finance'), [(100,)])
        self.assertEqual(self.run_query('SELECT SUM(Amount) FROM Expenses WHERE DeptID = 5 OR 1=1', 'finance'), [(30,)])

    def test_field_permissions_apply_to_projection_and_filter(self):
        for role in ['finance', 'management']:
            for sql in ['SELECT e.EmpName FROM Employees e', 'SELECT COUNT(*) FROM Employees WHERE BasicSalary > 500',
                        'SELECT COUNT(e.MobileNo) FROM Employees e', 'SELECT DateOfBirth AS total FROM Employees']:
                with self.subTest(role=role, sql=sql):
                    self.assertFalse(workspace._prepare_sql(sql, role, dept_id=3)[0])
        self.assertTrue(workspace._prepare_sql('SELECT BasicSalary FROM Payroll', 'finance', dept_id=3)[0])
        self.assertTrue(workspace._prepare_sql('SELECT EmpName FROM Employees', 'hr')[0])
        self.assertFalse(workspace._prepare_sql('SELECT CostPrice FROM Products', 'sales', region='South')[0])
        self.assertFalse(workspace._prepare_sql('SELECT SalesPerson FROM v_SalesOrders', 'management')[0])
        self.assertTrue(workspace._prepare_sql('SELECT SellingPrice FROM Products', 'sales', region='South')[0])

    def test_unknown_and_unassigned_roles_fail_closed(self):
        for role, region, dept in [('owner', None, None), ('sales', None, 3), ('finance', None, None)]:
            self.assertFalse(workspace._prepare_sql('SELECT COUNT(*) FROM Products', role, region, dept)[0])

    def test_sql_escape_attempts(self):
        attacks = ['SELECT * FROM Departments', 'SELECT Budget FROM Departments; DELETE FROM Departments',
                   'SELECT Budget FROM other.Departments', 'SELECT LOAD_FILE("secret") FROM Departments',
                   'SELECT Budget FROM Departments UNION SELECT PasswordHash FROM AppUsers',
                   'SELECT (SELECT PasswordHash FROM AppUsers LIMIT 1) FROM Departments',
                   'SELECT @@version FROM Departments', 'SELECT Budget INTO OUTFILE "dump" FROM Departments',
                   'SELECT Budget FROM Departments FOR UPDATE', 'SELECT Budget FROM Departments -- hidden',
                   'WITH x AS (SELECT Budget FROM Departments) SELECT Budget FROM x',
                   'SELECT Budget FROM Departments LIMIT -1', 'SELECT Budget FROM Departments LIMIT 0']
        for sql in attacks:
            with self.subTest(sql=sql):
                self.assertFalse(workspace._prepare_sql(sql, 'admin')[0])

    def test_limit_and_aliases(self):
        safe, _, sql, _ = workspace._prepare_sql('SELECT SUM(NetAmount) AS Revenue FROM SalesOrders ORDER BY Revenue LIMIT 500', 'sales', 'South')
        self.assertTrue(safe)
        self.assertIn('LIMIT 100', sql)
        self.assertFalse(workspace._prepare_sql('SELECT a.Budget FROM Departments a JOIN Departments a ON 1=1', 'admin')[0])

    def test_budget_typo_uses_real_department(self):
        with patch.object(workspace, 'execute_query', side_effect=[(['DeptID','DeptName','DeptCode'], [(5,'Information Technology','IT')]), (['DeptName','Budget'], [('Information Technology',2500000)])]):
            result = workspace._department_budget_lookup('whats the budjet of the it department', 'admin')
        self.assertEqual(result[2][0][1], 2500000)


class SessionAccessTests(unittest.TestCase):
    def setUp(self):
        self.client = workspace.app.test_client()
        self.token = 'test-session-secret'
        self.session_id = hashlib.sha256(self.token.encode()).hexdigest()
        self.user = {'user_id': 1, 'username': 'reviewer', 'full_name': 'Reviewer', 'role': 'sales', 'region': 'South', 'dept_id': 3}
        self.client.set_cookie(auth.COOKIE_NAME, self.token)

    def record(self, **changes):
        user = dict(self.user, **changes)
        return (1, 'reviewer', 'Reviewer', user['role'], user['region'], user['dept_id'],
                changes.get('active', 1), changes.get('password_hash', 'hash'), 'Finance',
                policy_fingerprint(self.user), hashlib.sha256(b'hash').hexdigest(), datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1))

    def test_anonymous_session_is_rejected(self):
        self.client.delete_cookie(auth.COOKIE_NAME)
        self.assertEqual(self.client.get('/session').status_code, 401)

    def test_live_authorization_and_capabilities(self):
        with patch.object(auth, 'execute_query', return_value=([], [self.record()])):
            response = self.client.get('/session')
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json['access']['canAudit'])
            self.assertEqual(self.client.get('/audit').status_code, 403)
            self.assertEqual(self.client.get('/access/users').status_code, 403)

    def test_disabled_changed_or_revoked_session_rejected(self):
        for change in [{'active': 0}, {'role': 'admin'}, {'region': 'North'}, {'dept_id': 5}, {'password_hash': 'changed'}]:
            with self.subTest(change=change), patch.object(auth, 'execute_query', return_value=([], [self.record(**change)])):
                self.client.set_cookie(auth.COOKIE_NAME, self.token)
                self.assertEqual(self.client.get('/session').status_code, 401)
        with patch.object(auth, 'execute_query', return_value=([], [])):
            self.assertEqual(self.client.get('/session').status_code, 401)

    def test_cookie_is_httponly_and_csrf_required(self):
        with workspace.app.test_request_context():
            response = auth.set_session_cookie(workspace.jsonify(ok=True), self.token)
            self.assertIn('HttpOnly', response.headers['Set-Cookie'])
            self.assertIn('SameSite=Strict', response.headers['Set-Cookie'])
        with patch.object(auth, 'execute_query', return_value=([], [self.record()])):
            self.assertEqual(self.client.post('/chat', json={'message': 'hello'}).status_code, 403)
            self.assertEqual(self.client.get('/session', headers={'X-Session-ID':'different-tab'}).status_code, 401)

    def test_logout_revokes_server_session(self):
        with patch.object(auth, 'execute_query', return_value=([], [self.record()])), patch.object(auth, '_write') as write:
            response = self.client.post('/logout', headers={'X-CSRF-Token':auth.csrf_token(self.session_id)})
            self.assertEqual(response.status_code, 200)
            self.assertIn('DELETE FROM AuthSessions', write.call_args.args[0])

    def test_account_service_outage_fails_closed(self):
        with patch.object(auth, 'execute_query', side_effect=RuntimeError('offline')):
            self.assertEqual(self.client.get('/session').status_code, 503)

    def test_cross_origin_login_rejected_and_responses_not_cached(self):
        self.assertEqual(self.client.post('/login', json={}, headers={'Origin':'https://elsewhere.invalid'}).status_code, 403)
        response = self.client.get('/')
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])

    def test_login_limit_rejects_before_password_lookup(self):
        with patch.object(workspace, 'enforce_rate_limit', return_value=False), patch.object(workspace, 'execute_query') as query:
            response = self.client.post('/login', json={'username': 'reviewer', 'password': 'wrong'})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers['Retry-After'], '300')
        query.assert_not_called()

    def test_account_change_during_query_hides_answer(self):
        user = dict(self.user, session_id=self.session_id, expires_at='2026-09-29T12:00:00+00:00')
        result = ('SELECT DeptName, Budget FROM Departments WHERE DeptID = 5',
                  ['DeptName', 'Budget'], [('Information Technology', 2500000)], ['Departments'])
        with patch.object(auth, 'resolve_user', return_value=(user, None, 200)), \
             patch.object(workspace, 'resolve_user', return_value=(None, 'Your account access has changed.', 401)), \
             patch.object(workspace, '_department_budget_lookup', return_value=result), \
             patch.object(workspace, 'enforce_rate_limit', return_value=True), \
             patch.object(workspace, 'log_audit'):
            response = self.client.post('/chat', json={'message': 'IT budget'},
                headers={'X-CSRF-Token': auth.csrf_token(self.session_id)})
        self.assertEqual(response.status_code, 401)
        self.assertNotIn('2500000', response.get_data(as_text=True))

    def test_audit_write_failure_is_not_silent(self):
        with patch.object(db, 'get_connection', side_effect=RuntimeError('offline')):
            with self.assertRaises(RuntimeError):
                db.log_audit(1, 'reviewer', 'admin', 'budget', 'SELECT Budget FROM Departments', 'Success')


if __name__ == '__main__':
    unittest.main()
