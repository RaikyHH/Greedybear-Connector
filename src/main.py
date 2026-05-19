import traceback

from pycti import OpenCTIConnectorHelper

from connector import ConnectorSettings, GreedyBearConnector

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = GreedyBearConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
