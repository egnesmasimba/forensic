import csv
from io import BytesIO, StringIO

from openpyxl import load_workbook
from app.models import CaseField, CaseFieldValue, User
from test_api import make_client
from test_privacy_education import admin, configure
from report_export import export_report


def add_case(client, title, score=0, **extra):
    result = client.post('/api/cases', json={'title': title, 'case_type': 'Other', 'score': score, **extra})
    assert result.status_code == 201, result.text
    return result.json()['id']


def test_filter_definitions_pagination_and_drilldown(tmp_path):
    with make_client(tmp_path) as client:
        first = add_case(client, 'Percent 100% review', 80)
        second = add_case(client, 'Other review', 40)
        add_case(client, 'Excluded', 5)
        with client.app.state.session_factory() as db:
            field = CaseField(case_type='Other', key='reference', label='Reference')
            db.add(field); db.flush()
            field_id = field.id
            db.add(CaseFieldValue(case_id=first, field_id=field_id, value='REF-001')); db.commit()
        key = f'field:{field_id}'
        definition = {'columns':['title','score',key], 'filters':[{'field':'score','operator':'gte','value':'40'}]}
        saved = client.post('/api/reports/definitions', json={'name':'Reviews', **definition})
        assert saved.status_code == 201, saved.text
        report_id = saved.json()['id']
        assert client.get('/api/reports/definitions').json()[0]['definition']['columns'] == definition['columns']
        page = client.get(f'/api/reports/definitions/{report_id}/data?limit=1').json()
        assert page['rows'][0]['values'][key] == 'REF-001'
        assert page['next_after_id'] == first
        next_page = client.get(f'/api/reports/definitions/{report_id}/data?limit=1&after_id={first}').json()
        assert next_page['rows'][0]['case_id'] == second
        assert next_page['rows'][0]['values'][key] is None
        assert next_page['next_after_id'] is None
        exported = StringIO()
        assert export_report(client, report_id, exported) == 2
        assert 'REF-001' in exported.getvalue()
        detail = client.get(f'/api/reports/cases/{first}/drilldown', params={'field':key}).json()
        assert detail['source']['field_definition_id'] == field_id
        assert detail['source']['record_id'] is not None and detail['value'] == 'REF-001'
        missing = client.get(f'/api/reports/cases/{second}/drilldown', params={'field':key}).json()
        assert missing['value'] is None and missing['source']['record_id'] is None
        for filters in [
            [{'field':key,'operator':'eq','value':'REF-001'}],
            [{'field':'title','operator':'contains','value':'100%'}],
            [{'field':'score','operator':'gte','value':'50'}, {'field':key,'operator':'eq','value':'REF-001'}],
        ]:
            response = client.post('/api/reports/query', json={'columns':['id'], 'filters':filters})
            assert [row['case_id'] for row in response.json()['rows']] == [first]
        any_match = client.post('/api/reports/query', json={'columns':['id'], 'match':'any', 'filters':[
            {'field':'score','operator':'gte','value':'80'}, {'field':'title','operator':'eq','value':'Other review'}]})
        assert len(any_match.json()['rows']) == 2


def test_invalid_filters_and_definition_permissions(tmp_path):
    with make_client(tmp_path) as client:
        add_case(client, 'Review')
        for condition in [
            {'field':'password_hash','operator':'eq','value':'x'},
            {'field':'score','operator':'contains','value':'1'},
            {'field':'score','operator':'gte','value':'not a number'},
            {'field':'score','operator':'eq','value':str(2**64)},
            {'field':'created_at','operator':'gte','value':'2026-01-01'},
        ]:
            assert client.post('/api/reports/query', json={'filters':[condition]}).status_code == 422
        assert client.post('/api/reports/query', json={'columns':['secret']}).status_code == 422
        assert client.post('/api/reports/query', json={'columns':['id','id']}).status_code == 422
        good_date = client.post('/api/reports/query', json={'filters':[{'field':'created_at','operator':'gte','value':'2000-01-01T02:00:00+02:00'}]})
        assert len(good_date.json()['rows']) == 1
        saved = client.post('/api/reports/definitions', json={'name':'Saved'}).json()
        assert client.post('/api/reports/definitions', json={'name':'Saved'}).status_code == 409
        with client.app.state.session_factory() as db:
            db.query(User).first().role = 'viewer'; db.commit()
        assert client.get(f"/api/reports/definitions/{saved['id']}/data").status_code == 200
        assert client.post('/api/reports/query', json={}).status_code == 200
        assert client.post('/api/reports/definitions', json={'name':'Another'}).status_code == 403
        assert client.delete(f"/api/reports/definitions/{saved['id']}").status_code == 403
        client.cookies.clear()
        assert client.get(f"/api/reports/definitions/{saved['id']}/data").status_code == 401


def test_external_csv_and_existing_spreadsheet_exports_are_safe(tmp_path):
    with make_client(tmp_path) as client:
        first = add_case(client, '=HYPERLINK("https://example.test")', 80)
        add_case(client, 'Next')
        saved = client.post('/api/reports/definitions', json={'name':'External','columns':['title']}).json()
        response = client.get(f"/api/reports/definitions/{saved['id']}/data?format=csv&limit=1")
        rows = list(csv.reader(StringIO(response.text)))
        assert rows[1][1].startswith("'=")
        assert response.headers['x-next-after-id'] == str(first)
        assert response.headers['cache-control'] == 'no-store'
        csv_report = client.get('/api/reports/cases.csv?columns=title').text
        assert list(csv.reader(StringIO(csv_report)))[1][0].startswith("'=")
        excel = client.get('/api/reports/cases.xlsx?columns=title')
        workbook = load_workbook(BytesIO(excel.content))
        assert workbook.active['A2'].data_type == 's'
        assert workbook.active['A2'].value.startswith("'=")


def test_privacy_mode_blocks_report_data_and_drilldown(tmp_path):
    with make_client(tmp_path) as client:
        case_id = add_case(client, 'Private')
        report_id = client.post('/api/reports/definitions', json={'name':'Private report'}).json()['id']
        admin(client); configure(client)
        for path in ['/api/reports/input-fields', '/api/reports/definitions',
                     f'/api/reports/definitions/{report_id}/data',
                     f'/api/reports/cases/{case_id}/drilldown?field=title']:
            assert client.get(path).status_code == 403
        assert client.post('/api/reports/query', json={}).status_code == 403
        assert client.get(f'/api/reports/definitions/{report_id}/data', headers={'X-Privacy-Raw':'1'}).status_code == 200


def test_external_connector_follows_pages_and_rejects_bad_cursor():
    import httpx
    import pytest
    calls = []
    def respond(request):
        after = int(request.url.params['after_id'])
        calls.append(after)
        return httpx.Response(200, json={'schema_version':1,
            'rows':[{'case_id':after + 1,'values':{'title':'Example'}}],
            'next_after_id':1 if after == 0 else None})
    with httpx.Client(base_url='https://example.test', transport=httpx.MockTransport(respond)) as client:
        output = StringIO()
        assert export_report(client, 1, output) == 2
        assert calls == [0, 1] and len(output.getvalue().splitlines()) == 2
    with httpx.Client(base_url='https://example.test', transport=httpx.MockTransport(lambda request: httpx.Response(
        200, json={'schema_version':1,'rows':[],'next_after_id':0}))) as client:
        with pytest.raises(ValueError, match='pagination'):
            export_report(client, 1, StringIO())
