"""One server-owned policy for SQL authorization and workspace capabilities.

SOURCE_COLUMNS mirrors database/01_create_db.sql and its four views.
Update it whenever the database schema changes.
"""

import hashlib
import json

ANALYTIC_TABLES = [
    "Departments", "Employees", "Shifts", "Qualifications",
    "LeaveTypes", "LeaveEligibility", "LeaveTransactions", "Attendance",
    "Products", "Categories", "Warehouses", "Inventory", "StockMovements",
    "Customers", "SalesOrders", "SalesOrderItems", "SalesReturns",
    "Accounts", "FinancialTransactions", "Payroll", "Expenses",
    "v_SalesOrders", "v_InventoryStatus", "v_FinancialSummary", "v_ManagementKPI",
]

ROLE_TABLES = {
    "admin": ANALYTIC_TABLES,
    "sales": [
        "SalesOrders", "SalesOrderItems", "SalesReturns", "Customers",
        "Products", "Categories", "v_SalesOrders",
    ],
    "inventory": [
        "Inventory", "Products", "Categories", "Warehouses", "StockMovements",
        "v_InventoryStatus",
    ],
    "finance": [
        "FinancialTransactions", "Accounts", "Payroll", "Expenses",
        "v_FinancialSummary", "Departments", "Employees",
    ],
    "hr": [
        "Employees", "Departments", "Shifts", "LeaveTypes", "LeaveEligibility",
        "LeaveTransactions", "Attendance", "Payroll", "Qualifications",
    ],
    "management": [
        "v_SalesOrders", "v_InventoryStatus", "v_FinancialSummary",
        "v_ManagementKPI", "SalesOrders", "Employees", "Departments",
    ],
}

SOURCE_COLUMNS = {
    'Departments': [
        'DeptID', 'DeptName', 'DeptCode', 'Location', 'ManagerID', 'Budget', 'Status',
        'CreatedAt',
    ],
    'Shifts': [
        'ShiftID', 'ShiftName', 'ShiftCode', 'StartTime', 'EndTime', 'Status',
    ],
    'Qualifications': [
        'QualID', 'QualName',
    ],
    'Employees': [
        'EmployeeID', 'EmpCode', 'EmpName', 'Gender', 'DateOfBirth', 'JoinDate', 'DeptID',
        'ShiftID', 'Designation', 'QualificationID', 'BasicSalary', 'MobileNo', 'Branch',
        'Status', 'CreatedAt',
    ],
    'LeaveTypes': [
        'LeaveTypeID', 'LeaveTypeName', 'TypeCode', 'MaxDaysPerYear',
    ],
    'LeaveEligibility': [
        'EligID', 'EmployeeID', 'LeaveTypeID', 'Year', 'EligibleDays', 'AvailedDays',
        'BalanceDays',
    ],
    'LeaveTransactions': [
        'LeaveID', 'EmployeeID', 'LeaveTypeID', 'FromDate', 'ToDate', 'LeaveDays', 'Reason',
        'Status', 'ApprovedBy', 'ApprovedDate', 'ApplicationDate',
    ],
    'Attendance': [
        'AttendanceID', 'EmployeeID', 'AttDate', 'InTime', 'OutTime', 'WorkHours', 'Status',
    ],
    'Categories': [
        'CategoryID', 'CategoryName', 'CategoryCode', 'Description',
    ],
    'Products': [
        'ProductID', 'ProductCode', 'ProductName', 'CategoryID', 'UnitOfMeasure', 'CostPrice',
        'SellingPrice', 'ReorderLevel', 'Status', 'CreatedAt',
    ],
    'Warehouses': [
        'WarehouseID', 'WarehouseName', 'Location', 'ManagerID', 'Capacity',
    ],
    'Inventory': [
        'InventoryID', 'ProductID', 'WarehouseID', 'QuantityOnHand', 'QuantityReserved',
        'LastUpdated',
    ],
    'StockMovements': [
        'MovementID', 'ProductID', 'WarehouseID', 'MovementType', 'Quantity', 'ReferenceNo',
        'Remarks', 'MovementDate', 'CreatedAt',
    ],
    'Customers': [
        'CustomerID', 'CustomerCode', 'CustomerName', 'Region', 'City', 'ContactPerson',
        'Phone', 'Email', 'CreditLimit', 'Status', 'CreatedAt',
    ],
    'SalesOrders': [
        'OrderID', 'OrderNo', 'OrderDate', 'CustomerID', 'SalesPersonID', 'Region', 'Status',
        'TotalAmount', 'DiscountAmount', 'TaxAmount', 'NetAmount', 'DeliveryDate', 'Remarks',
        'CreatedAt',
    ],
    'SalesOrderItems': [
        'ItemID', 'OrderID', 'ProductID', 'Quantity', 'UnitPrice', 'Discount', 'LineTotal',
    ],
    'SalesReturns': [
        'ReturnID', 'ReturnNo', 'ReturnDate', 'OrderID', 'Reason', 'ReturnAmount', 'Status',
    ],
    'Accounts': [
        'AccountID', 'AccountCode', 'AccountName', 'AccountType', 'ParentAccountID', 'Status',
    ],
    'FinancialTransactions': [
        'TransactionID', 'TransactionNo', 'TransactionDate', 'AccountID', 'TransactionType',
        'Amount', 'Description', 'ReferenceNo', 'ReferenceType', 'CreatedBy', 'CreatedAt',
    ],
    'Payroll': [
        'PayrollID', 'EmployeeID', 'PayMonth', 'PayYear', 'BasicSalary', 'Allowances',
        'Deductions', 'GrossSalary', 'NetSalary', 'PaymentDate', 'Status',
    ],
    'Expenses': [
        'ExpenseID', 'ExpenseDate', 'Category', 'Description', 'Amount', 'DeptID',
        'ApprovedBy', 'Status', 'CreatedAt',
    ],
    'v_SalesOrders': [
        'OrderID', 'OrderNo', 'OrderDate', 'Status', 'TotalAmount', 'DiscountAmount',
        'TaxAmount', 'NetAmount', 'Region', 'DeliveryDate', 'CustomerName', 'City',
        'SalesPerson',
    ],
    'v_InventoryStatus': [
        'ProductID', 'ProductCode', 'ProductName', 'CategoryName', 'WarehouseName',
        'QuantityOnHand', 'QuantityReserved', 'AvailableQty', 'ReorderLevel', 'StockStatus',
        'CostPrice', 'SellingPrice', 'LastUpdated',
    ],
    'v_FinancialSummary': [
        'TransactionID', 'TransactionNo', 'TransactionDate', 'TransactionType', 'Amount',
        'Description', 'ReferenceNo', 'ReferenceType', 'AccountCode', 'AccountName',
        'AccountType',
    ],
    'v_ManagementKPI': [
        'Metric', 'Value', 'Period',
    ],
}

POLICY_VERSION = "2026-09-30.1"
ROLE_DETAILS = {
    "admin": ("Administrator", "Business analytics", "Organization-wide business data and audit activity"),
    "sales": ("Sales", "Sales analytics", "Orders, customers and returns in your assigned region"),
    "inventory": ("Inventory", "Inventory analytics", "Products, warehouses and stock across the organization"),
    "finance": ("Finance", "Finance analytics", "Organization-wide ledger; payroll, expenses and budgets in your department"),
    "hr": ("People", "People analytics", "Organization-wide employee, attendance, leave and payroll records"),
    "management": ("Management", "Management analytics", "Operational summaries and workforce structure; personal employee fields restricted"),
}
ROLE_QUESTIONS = {
    "admin": ["What is the budget of the IT department?", "Compare sales by month this year", "Which products are below reorder level?", "Count active employees by department"],
    "sales": ["Show sales in my region this month", "Which customers had the highest net sales?", "List recently delivered orders", "Show top selling products this quarter"],
    "inventory": ["Which products are below reorder level?", "Show available stock by warehouse", "List stock movements this month", "Which products have reserved inventory?"],
    "finance": ["What is sales revenue this month?", "Show expenses by category this year", "Show pending payroll for my department", "List transactions by account this quarter"],
    "hr": ["Count active employees by department", "List pending leave requests", "Summarize attendance this month", "Show leave balances by employee"],
    "management": ["Summarize the current month business KPIs", "Compare sales by month this year", "Count products below reorder level", "Show headcount by department"],
}


def access_problem(role, region=None, dept_id=None):
    if not isinstance(role, str) or not role.strip():
        return "This account has no supported workspace role. Contact your administrator."
    if role == "sales" and (not isinstance(region, str) or not region.strip()):
        return "Your sales account needs a region assignment. Contact your administrator."
    if role == "finance" and (not isinstance(dept_id, int) or isinstance(dept_id, bool) or dept_id < 1):
        return "Your finance account needs a department assignment. Contact your administrator."
    return None


def policy_fingerprint(user):
    grants = user.get("data_access") or {}
    canonical_grants = {name: sorted(columns) for name, columns in sorted(grants.items())}
    value = [POLICY_VERSION, user["user_id"], user.get("role_id"), user["role"],
             user.get("region"), user.get("dept_id"), user.get("data_access_mode"), canonical_grants]
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def columns_for(role, source):
    key = next((name for name in SOURCE_COLUMNS if name.lower() == source.lower()), None)
    if not key or key not in ROLE_TABLES.get(role, []):
        return []
    if key == "Employees":
        if role == "finance":
            return ["EmployeeID", "DeptID"]
        if role == "management":
            return ["EmployeeID", "DeptID", "Designation", "Branch", "Status", "JoinDate"]
    if key == "Products" and role == "sales":
        return ["ProductID", "ProductCode", "ProductName", "CategoryID",
                "UnitOfMeasure", "SellingPrice", "Status"]
    if key == "v_SalesOrders" and role == "management":
        return [column for column in SOURCE_COLUMNS[key] if column != "SalesPerson"]
    return SOURCE_COLUMNS[key]


def source_scope(role, source, user):
    if role == "sales" and source in {"SalesOrders", "SalesOrderItems", "SalesReturns", "Customers", "v_SalesOrders"}:
        return "Region: " + str(user.get("region") or "Unassigned")
    if role == "finance" and source in {"Payroll", "Expenses", "Employees", "Departments"}:
        return "Department: " + str(user.get("dept_name") or user.get("dept_id") or "Unassigned")
    return "Organization-wide"


def capabilities(user):
    role = str(user["role"]).lower()
    fallback = (role.replace("_", " ").title(), "Business data", "Access assigned by your workspace administrator")
    label, kicker, description = ROLE_DETAILS.get(role, fallback)
    description = user.get("role_description") or description
    sources = user.get("data_access") if "data_access" in user else {
        name: columns_for(role, name) for name in ROLE_TABLES.get(role, [])
    }
    role_questions = ROLE_QUESTIONS.get(role, [])
    return {
        "label": label, "kicker": kicker, "description": description,
        "canQuery": True, "canAudit": role == "admin", "canReviewAccess": role == "admin",
        "canManageUsers": role == "admin", "canManageRoles": role == "admin", "canViewSchema": role == "admin",
        "canExport": True, "maxRows": 100, "policyVersion": POLICY_VERSION,
        "fingerprint": policy_fingerprint(user), "questions": role_questions,
        "sources": [{"name": name, "scope": source_scope(role, name, user),
                     "columns": list(columns)} for name, columns in sources.items()],
    }
