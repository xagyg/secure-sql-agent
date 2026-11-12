-- Closure table for Northwind's manager hierarchy - SQL Server.
--
-- One row per (manager, employee at any depth below them), plus a row
-- for each employee as their own manager, so a grant of "self" on
-- ManagerID covers the user and their whole team. The agent's row filter
-- then carries one value - the user's EmployeeID - however big the team
-- is (README "Large scopes"; docs/examples/closure-table/README.md).
--
-- Run as an administrator, NOT as the agent's read-only login:
--     sqlcmd -S BRAD-Z640 -d Northwind -E -i employee_hierarchy.sqlserver.sql
-- Run it again whenever ReportsTo changes (an HR feed, or a nightly SQL
-- Agent job): the refresh below replaces the contents in one
-- transaction, so the agent never sees a half-built table.

-- 1. The table (once). Two foreign keys to Employees - which is why the
--    security policy must name the join for this table (join: below).
IF OBJECT_ID(N'dbo.EmployeeHierarchy', N'U') IS NULL
CREATE TABLE dbo.EmployeeHierarchy (
    ManagerID  int NOT NULL
        CONSTRAINT FK_EmployeeHierarchy_Manager  REFERENCES dbo.Employees (EmployeeID),
    EmployeeID int NOT NULL
        CONSTRAINT FK_EmployeeHierarchy_Employee REFERENCES dbo.Employees (EmployeeID),
    CONSTRAINT PK_EmployeeHierarchy PRIMARY KEY (ManagerID, EmployeeID)  -- the filter's lookup
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes
               WHERE name = N'IX_EmployeeHierarchy_EmployeeID'
                 AND object_id = OBJECT_ID(N'dbo.EmployeeHierarchy'))
CREATE INDEX IX_EmployeeHierarchy_EmployeeID
    ON dbo.EmployeeHierarchy (EmployeeID);                              -- the join back to Employees
GO
-- The agent's login (sqlagent_ro, db_datareader) can read it already;
-- nothing to grant.

-- 2. The refresh (every time).
SET XACT_ABORT ON;      -- any error rolls the whole refresh back
BEGIN TRANSACTION;
DELETE FROM dbo.EmployeeHierarchy;
WITH Tree (ManagerID, EmployeeID) AS (
    SELECT EmployeeID, EmployeeID FROM dbo.Employees          -- everyone, as their own manager
    UNION ALL
    SELECT t.ManagerID, e.EmployeeID
    FROM Tree AS t
    JOIN dbo.Employees AS e ON e.ReportsTo = t.EmployeeID
)
INSERT INTO dbo.EmployeeHierarchy (ManagerID, EmployeeID)
SELECT ManagerID, EmployeeID FROM Tree
OPTION (MAXRECURSION 100);  -- a ReportsTo cycle fails here and rolls back
COMMIT;
GO

-- Check: how many people each manager covers (themselves included).
-- SELECT ManagerID, COUNT(*) FROM dbo.EmployeeHierarchy GROUP BY ManagerID ORDER BY 1;
