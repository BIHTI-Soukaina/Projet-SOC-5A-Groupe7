# Installez les bibliothèques suivantes pour exécuter ce script : splunk-sdk, splunklib, jinja2
import splunklib.client as client
from jinja2 import Template
import json
import datetime


# Connexion à Splunk
service = client.connect(
    host='localhost',
    port='8089',
    scheme='https',
    username='do_not_use_admin',
    password='insert_mdp_here'
)
# Requête de recherche Splunk
search_query = 'search index="alerts" event_title="*"'
# Envoi de la requête de recherche à Splunk
search_results = service.jobs.oneshot(search_query, output_mode='json')
# Récupération des résultats de la recherche au format JSON
jsout = json.loads(search_results.read())

# Enregistrement des résultats dans un fichier JSON : Cela peut vous aider à comprendre le format des données retournées par Splunk
# Décommentez les 3 lignes ci-dessous pour enregistrer les résultats dans un fichier JSON
# json_formatted_str = json.dumps(jsout, indent=2)
# with open('data.json', 'w') as f:
#     f.write(json_formatted_str)

# Modèle de bulletin d'alerte en Markdown
template= """
{% for result in jsout['results'] %}
# Alerte : {{ result['event_title'] }}
    Source : **{{ result['source'] }}**
    Horodatage : {{ datetime.datetime.fromisoformat(result['_time']) }}
    Instance Splunk : {{ result['host'] }}
{% endfor %}
"""
# Initialisation de notre template Jinja
jinja_template = Template(template)
# Pour utiliser une bibliothèque Python dans votre template Jinja, il faut l'importer dans l'appel à la méthode render ci dessous :
print(jinja_template.render(jsout=jsout, datetime=datetime))

service.logout()