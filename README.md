# SSE Implementation

# Dependencies

The python dependencies of the project are written in requirements.txt file. Install all the requirements before running the project.

# How To
To use this SSE implementation, you must first have the server running:

	python sse_server.py

Then invoke the client with one of the requisite options:

	python client.py <OPTION>

It is also required that the user has access to some set of audit log file.

## Options
    -s, --search "<term(s)>"
        Search for term or terms in quotations

    -u, --update "<file>"
        Updates a single file, included appending local index, appending encrypted remote index, encrypting "file", and sending it to server.
