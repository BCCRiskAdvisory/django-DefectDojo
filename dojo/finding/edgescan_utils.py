from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404

from dojo.models import Finding, Product_API_Scan_Configuration
from dojo.tools.api_edgescan.api_client import EdgescanAPI


def trigger_vulnerability_retest(fid):
    """
    Perform a vulnerability retest for a specific Finding by calling the Edgescan external API.

    Args:
        unique_id_from_tool (int): The ID (in Edgescan DB) of the Vulnerability to request a retest for.

    Notes:
        - This function is called by the minimal view `request_vulnerability_retest`.
        - Keeps all business logic in one place, reducing merge conflicts in views.py.

    """
    finding = get_object_or_404(Finding, id=fid)
    client, _config = prepare_client(finding.test)
    return client.request_vlnerability_retest(finding.unique_id_from_tool)


def prepare_client(test):
    product = test.engagement.product
    if test.api_scan_configuration:
        config = test.api_scan_configuration
        if config.product != product:
            msg = (
                "API Scan Configuration for Edgescan and Product do not match. "
                f'Product: "{product.name}" ({product.id}), config.product: "{config.product.name}" ({config.product.id})'
            )
            raise ValidationError(msg)
    else:
        configs = Product_API_Scan_Configuration.objects.filter(
            product=product,
        )
        if configs.count() == 1:
            config = configs.first()
        elif configs.count() > 1:
            msg = (
                "More than one Product API Scan Configuration has been configured, but none of them has been "
                "chosen.\nPlease specify at Test which one should be used. "
                f'Product: "{product.name}" ({product.id})'
            )
            raise ValidationError(msg)
        else:
            msg = (
                "There are no API Scan Configurations for this Product.\n"
                "Please add at least one API Scan Configuration for Edgescan to this Product. "
                f'Product: "{product.name}" ({product.id})'
            )
            raise ValidationError(msg)

    tool_config = config.tool_configuration
    return EdgescanAPI(tool_config), config
