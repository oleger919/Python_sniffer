from multiprocessing import Process, Queue

sentinel = -1
q = 0
data = 0


class Create:
    def __init__(self):
        global data, q
        self.data = data
        self.q = q

    def creator(self):
        """
        Creates data to be consumed and waits for the consumer
        to finish processing
        """
        print('Creating data and putting it on the queue')
        for item in self.data:
            self.q.put(item)





def my_consumer(q):
    """
    Consumes some data and works on it
    In this case, all it does is double the input
    """
    while True:
        data = q.get()
        print('data found to be processed: {}'.format(data))

        processed = data * 2
        print(processed)

        if data is sentinel:
            break


if __name__ == '__main__':
    q = Queue()
    data = [5, 10, 13, -1, 67]
    my_creator = Create()
    process_one = Process(target=my_creator.creator)
    process_two = Process(target=my_consumer, args=(q,))

    process_one.start()
    process_two.start()

    q.close()
    q.join_thread()

    process_one.join()
    process_two.join()
