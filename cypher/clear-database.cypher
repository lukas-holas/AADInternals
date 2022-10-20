CALL apoc.periodic.commit(
	'MATCH (n) WITH n LIMIT $limit DETACH DELETE n RETURN count(*)', {limit: 10000})
YIELD updates, executions, runtime, batches
RETURN updates, executions, runtime, batches;

CALL apoc.schema.assert({},{},true) YIELD label, key RETURN *