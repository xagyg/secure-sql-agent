-- Closure table for Northwind's manager hierarchy - PostgreSQL.
--
-- One row per (manager, employee at any depth below them), plus a row
-- for each employee as their own manager, so a grant of "self" on
-- manager_id covers the user and their whole team. The agent's row filter
-- then carries one value - the user's employee_id - however big the team
-- is (README "Large scopes"; docs/examples/closure-table/README.md).
--
-- Run as the database owner, NOT as the agent's read-only login:
--     psql -U postgres -d northwind -f employee_hierarchy.postgres.sql
-- Run it again whenever reports_to changes (an HR feed, or nightly): the
-- refresh below replaces the contents in one transaction, so the agent
-- never sees a half-built table.

-- 1. The table (once). Two foreign keys to employees - which is why the
--    security policy must name the join for this table (join: below).
CREATE TABLE IF NOT EXISTS public.employee_hierarchy (
    manager_id  smallint NOT NULL REFERENCES public.employees (employee_id),
    employee_id smallint NOT NULL REFERENCES public.employees (employee_id),
    PRIMARY KEY (manager_id, employee_id)       -- the filter's lookup
);
CREATE INDEX IF NOT EXISTS employee_hierarchy_employee_id
    ON public.employee_hierarchy (employee_id); -- the join back to employees

-- The agent's login reads it like any other table.
GRANT SELECT ON public.employee_hierarchy TO sqlagent_ro;

-- 2. The refresh (every time).
BEGIN;
DELETE FROM public.employee_hierarchy;
INSERT INTO public.employee_hierarchy (manager_id, employee_id)
WITH RECURSIVE tree (manager_id, employee_id) AS (
    SELECT employee_id, employee_id FROM public.employees     -- everyone, as their own manager
    UNION                                                     -- UNION, not UNION ALL: stops on a reports_to cycle
    SELECT t.manager_id, e.employee_id
    FROM tree AS t
    JOIN public.employees AS e ON e.reports_to = t.employee_id
)
SELECT manager_id, employee_id FROM tree;
COMMIT;

-- Check: how many people each manager covers (themselves included).
-- SELECT manager_id, COUNT(*) FROM public.employee_hierarchy GROUP BY manager_id ORDER BY 1;
