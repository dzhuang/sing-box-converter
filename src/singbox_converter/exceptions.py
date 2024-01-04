class InvalidSubscriptionsJsonFile(Exception):
    pass


class InvalidSubscriptionsConfig(Exception):
    pass


class FailedToParseSubscription(Exception):
    pass


class NoTemplateConfigured(Exception):
    pass


class InvalidTemplate(Exception):
    pass


class UnknownRuleSet(Exception):
    pass


class FailedToFetchSubscription(Exception):
    pass
