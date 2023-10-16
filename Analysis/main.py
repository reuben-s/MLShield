from pywinpipes import PipeServer

PIPE_NAME = "TestPipe"

def new_message(client, message):
    print(f"New message recieved from remote process! \"{message}\"")
    # client.send_message("Response from server") This blocks so ignore for now

if __name__ == "__main__":
    pipe_sever = PipeServer(PIPE_NAME, new_message=new_message)