Sky is a Python (3.4) library and command-line tool for rapid deployment of
cloud infrastructures. It supports DevOps by defining infrastructure as code
and orchestrating resource creation and termination.

The command line tool is an application-level interface to
`Amazon Web Services <http://aws.amazon.com/>`_ that leverages the ``boto``
library.

Typical use involves the creation of a Python module with one or more
functions, then executing them via the ``sky`` command-line tool. Below is an
example "skyfile" that places an Amazon EC2 instance (a server) within a
Virtual Private Cloud (a private network).

.. code-block:: python

    from sky.api import create_network, create_instances

    @permanent
    @infrastructure
    def network():
        virtual_network = create_network(network_class='b',
                                         internet_connected=True)
        public_subnets = create_subnets(virtual_network,
                                        zones='us-east-1b',
                                        byte_aligned=True,
                                        public=True)
        
    @ephemeral
    @infrastructure(requires=['network'])
    def application():
        instances = create_instances(ready.network.public_subnets,
                                     internet_addressable=True,
                                     role='application')

Note that the ``infrastructure`` decorator denotes a function as a cloud
resource, to be created by the ``sky`` command-line tool. This decorator takes
an optional ``requires`` argument, where requisite infrastructure can be listed.

A special ``ready`` Object allows downstream infrastructure to access resources
that it depends on.

Once an infrastructure is defined, it may be deployed to AWS, like so::

    $ sky deploy

In addition to use via the ``sky`` tool, Sky's components may be imported
into other Python code, providing a Pythonic interface to cloud services, such
as Amazon Web Services.
