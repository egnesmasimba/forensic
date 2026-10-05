"use strict";
(() => {
    let fields = [], saved = [];
    let next = null, runningDefinition = null;
    const selection = () => ({
        columns: [...$('rb-columns').selectedOptions].map(option => option.value),
        match: $('rb-match').value,
        filters: [...$('rb-filters').children].map(row => ({
            field: row.querySelector('[data-field]').value,
            operator: row.querySelector('[data-operator]').value,
            value: row.querySelector('input').value
        }))
    });
    function addFilter(value = {}) {
        const field = el('select', { 'data-field': '', 'aria-label': 'Filter field' });
        for (const item of fields)
            field.append(el('option', { value: item.key }, [item.label]));
        field.value = value.field || 'status';
        const operator = el('select', { 'data-operator': '', 'aria-label': 'Comparison' });
        const input = el('input', { maxlength: 500, 'aria-label': 'Filter value' });
        input.value = value.value || '';
        function operators() {
            const meta = fields.find(item => item.key === field.value);
            operator.replaceChildren(...(meta?.operators || []).map(op => el('option', { value: op }, [{ eq: 'Equals', contains: 'Contains', gte: 'At least / on or after', lte: 'At most / on or before' }[op]])));
            input.placeholder = meta?.type === 'date' ? '2026-01-01T00:00:00Z' : 'Value';
        }
        operators();
        if (value.operator)
            operator.value = value.operator;
        field.addEventListener('change', operators);
        const remove = el('button', { type: 'button' }, ['Remove']);
        const row = el('div', { class: 'filters' }, [field, operator, input, remove]);
        remove.addEventListener('click', () => row.remove());
        $('rb-filters').append(row);
    }
    async function loadDefinitions() {
        saved = await api('/api/reports/definitions');
        $('rb-saved').replaceChildren(el('option', { value: '' }, ['Choose a definition']), ...saved.map(row => el('option', { value: row.id }, [row.name])));
        $('rb-integration').replaceChildren();
    }
    function integration() {
        const row = saved.find(item => String(item.id) === $('rb-saved').value);
        const box = $('rb-integration');
        box.replaceChildren();
        if (!row)
            return;
        const path = `/api/reports/definitions/${row.id}/data`;
        box.append(el('p', {}, [`External tools can read the saved “${row.name}” definition using an authenticated JSON request. Follow next_after_id until it is null. Results reflect current records.`]), el('code', {}, [new URL(path, location.origin).href]), el('p', {}, ['CSV downloads contain up to 500 rows per page; X-Next-After-ID identifies the next page.']), el('a', { href: `${path}?format=csv&limit=500` }, ['Download first CSV page of saved definition']));
    }
    async function preview(after = 0) {
        if (!after)
            runningDefinition = selection();
        const page = await api(`/api/reports/query?after_id=${after}&limit=100`, { method: 'POST', body: JSON.stringify(runningDefinition) });
        const table = el('table');
        table.append(el('thead', {}, [el('tr', {}, page.columns.map(column => el('th', {}, [column.label])))]));
        const body = el('tbody');
        for (const row of page.rows) {
            body.append(el('tr', {}, page.columns.map(column => {
                const value = row.values[column.key];
                const button = el('button', { type: 'button', class: 'secondary' }, [value == null ? '(not recorded)' : String(value)]);
                button.addEventListener('click', () => run(async () => {
                    const detail = await api(`/api/reports/cases/${row.case_id}/drilldown?field=${encodeURIComponent(column.key)}`);
                    $('rb-drilldown').textContent = JSON.stringify(detail, null, 2);
                }));
                return el('td', {}, [button]);
            })));
        }
        table.append(body);
        $('rb-results').replaceChildren(table);
        $('rb-drilldown').textContent = '';
        next = page.next_after_id;
        $('rb-next').hidden = next == null;
        $('rb-status').textContent = `${page.rows.length} cases on this page${next ? '; more results available' : '; end of results'}.`;
    }
    $('report-builder-open').addEventListener('click', () => run(async () => {
        fields = await api('/api/reports/input-fields');
        $('rb-columns').replaceChildren(...fields.map(field => el('option', { value: field.key }, [field.label])));
        for (const option of $('rb-columns').options)
            option.selected = ['id', 'title', 'status', 'score'].includes(option.value);
        $('rb-filters').replaceChildren();
        $('rb-results').replaceChildren();
        $('rb-drilldown').textContent = '';
        $('rb-status').textContent = '';
        $('rb-next').hidden = true;
        for (const id of ['rb-save', 'rb-delete', 'rb-name-label'])
            $(id).hidden = state.user?.role === 'viewer';
        await loadDefinitions();
        $('report-builder-dialog').showModal();
    }));
    $('rb-add').addEventListener('click', () => addFilter());
    $('rb-preview').addEventListener('click', () => run(() => preview()));
    $('rb-sql').addEventListener('click', () => run(async () => {
        const page = await api('/api/reports/sql/case-status');
        const table = el('table');
        table.append(el('thead', {}, [el('tr', {}, [el('th', {}, ['Status']), el('th', {}, ['Cases'])])]));
        const body = el('tbody');
        for (const row of page.rows)
            body.append(el('tr', {}, [el('td', {}, [row.status]), el('td', {}, [String(row.case_count)])]));
        table.append(body);
        $('rb-results').replaceChildren(table);
        $('rb-status').textContent = `SQL status summary from ${page.source}.`;
        $('rb-next').hidden = true;
    }));
    $('rb-next').addEventListener('click', () => run(() => preview(next ?? 0)));
    $('rb-saved').addEventListener('change', integration);
    $('rb-load').addEventListener('click', () => run(async () => {
        const row = saved.find(item => String(item.id) === $('rb-saved').value);
        if (!row)
            throw new Error('Choose a saved definition');
        $('rb-match').value = row.definition.match;
        for (const option of $('rb-columns').options)
            option.selected = row.definition.columns.includes(option.value);
        $('rb-filters').replaceChildren();
        row.definition.filters.forEach(addFilter);
        await preview();
    }));
    $('rb-save').addEventListener('click', () => run(async () => {
        const row = await api('/api/reports/definitions', { method: 'POST', body: JSON.stringify({ ...selection(), name: $('rb-name').value }) });
        await loadDefinitions();
        $('rb-saved').value = String(row.id);
        integration();
        toast('Report definition saved');
    }));
    $('rb-delete').addEventListener('click', () => run(async () => {
        if (!$('rb-saved').value)
            throw new Error('Choose a saved definition');
        await api(`/api/reports/definitions/${$('rb-saved').value}`, { method: 'DELETE' });
        await loadDefinitions();
        toast('Report definition deleted');
    }));
})();
