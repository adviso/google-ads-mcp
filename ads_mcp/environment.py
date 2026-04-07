from os import getenv

VARIABLES = [
    "ENV",
    "GCP_PROJECT",
    "GOOGLE_ADS_MCP_SERVER_HOST",
    "GOOGLE_ADS_MCP_SERVER_PATH",
    "GOOGLE_ADS_MCP_SERVER_PORT",
    "WORKOS_AUTHKIT_ISSUER_URL",
]

CONCATENATED_VARIABLES = {
    "GOOGLE_ADS_MCP_SERVER_URL": [
        "GOOGLE_ADS_MCP_SERVER_HOST",
        "GOOGLE_ADS_MCP_SERVER_PATH",
    ],
}


class Environment:
    def __init__(self):
        self.variables = {variable: getenv(variable) for variable in VARIABLES}
        self.validate()
        for variable, concatenated_variables in CONCATENATED_VARIABLES.items():
            self.variables[variable] = "".join(
                [
                    value
                    for value in [
                        self.variables.get(concatenated_variable)
                        for concatenated_variable in concatenated_variables
                    ]
                    if value is not None
                ]
            )

    def validate(self) -> None:
        for variable in VARIABLES:
            if self.get(variable) is None:
                raise ValueError(f"Environment variable {variable} is not set")
            if self.get(variable) == "":
                raise ValueError(f"Environment variable {variable} is empty")

    def get(self, variable: str) -> str | None:
        return self.variables[variable]


environment = Environment()
