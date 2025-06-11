import os

from dotenv import load_dotenv
from langsmith import Client

load_dotenv()

client = Client(api_key=os.getenv("LANGSMITH_API_KEY"))


def get_run_cost(run_id):
    run_data = client.read_run(run_id)
    run_data.total_cost
