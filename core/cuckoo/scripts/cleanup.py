# Copyright (C) 2019-2021 Estonian Information System Authority.
# See the file 'LICENSE' for copying permission.

import click
import logging

from cuckoo.common.log import exit_error, print_info
from cuckoo.common.startup import StartupError
from cuckoo.common.storage import cuckoocwd, CWDError
from cuckoo.common.analyses import States, delete_analysis_disk, delete_analysis_db

def start_export(older_than_days, loglevel, without_confirm=False):
    from cuckoo.common.log import set_logger_level
    from cuckoo.common.startup import init_global_logging, init_database
    from cuckoo.common.clients import APIClient
    from cuckoo.common.config import (
        cfg, MissingConfigurationFileError, ConfigurationError
    )
    from cuckoo.common.storage import Paths
    from ..clean import find_analyses, AnalysisRemoteExporter, CleanerError

    init_global_logging(loglevel, Paths.log("export.log"))
    set_logger_level("urllib3.connectionpool", logging.ERROR)
    try:
        api_url = cfg(
            "cuckoo.yaml", "remote_storage", "api_url", load_missing=True
        )
        api_key = cfg(
            "cuckoo.yaml", "remote_storage", "api_key", load_missing=True
        )
    except MissingConfigurationFileError as e:
        raise StartupError(f"Missing configuration file: {e}")
    except ConfigurationError as e:
        raise StartupError(e)

    if not api_url or not api_key:
        raise StartupError(
            "Remote storage API url or API key not set in cuckoo.conf"
        )

    init_database()
    analyses, date = find_analyses(older_than_days, States.FINISHED)
    if not analyses:
        print_info(f"No finished analyses older than {date} found.")
        return

    print_info(f"Found {len(analyses)} older than {date}")
    if not without_confirm and not click.confirm(
            f"Export and delete {len(analyses)} analyses? "
            f"This cannot be undone."
        ):
            return

    api_client = APIClient(api_url, api_key)
    with AnalysisRemoteExporter([a.id for a in analyses], api_client) as ex:
        try:
            ex.start()
        except CleanerError as e:
            raise StartupError(e)

def delete_analyses(state, older_than_hours, loglevel, without_confirm=False):
    from cuckoo.common.log import set_logger_level
    from cuckoo.common.startup import init_global_logging, init_database
    from cuckoo.common.clients import APIClient
    from cuckoo.common.config import (
        cfg, MissingConfigurationFileError, ConfigurationError
    )
    from cuckoo.common.storage import Paths
    from ..clean import find_analyses_hours, AnalysisRemoteExporter, CleanerError

    init_global_logging(loglevel, Paths.log("delete.log"))
    set_logger_level("urllib3.connectionpool", logging.ERROR)

    init_database()
    if not state in States.list():
        exit_error(f"Invalid state: {state}")
    analyses, date = find_analyses_hours(older_than_hours, state)
    if not analyses:
        print_info(f"No {state} analyses older than {date} found.")
        return

    print_info(f"Found {len(analyses)} {state} older than {date}")
    if not without_confirm and not click.confirm(
            f"Delete {len(analyses)} analyses? "
            f"This cannot be undone."
        ):
            return

    for a in analyses:
        try:
            delete_analysis_db(a.id)
            delete_analysis_disk(a.id)
        except (ResultDoesNotExistError):
            print_info(f"Not found {a.id}.")

def delete_analysis_by_id(analysis_id, loglevel):
    from cuckoo.common.log import set_logger_level
    from cuckoo.common.startup import init_global_logging, init_database
    from cuckoo.common.clients import APIClient
    from cuckoo.common.config import (
        cfg, MissingConfigurationFileError, ConfigurationError
    )
    from cuckoo.common.storage import Paths
    from ..clean import find_analyses_hours, AnalysisRemoteExporter, CleanerError

    init_global_logging(loglevel, Paths.log("delete.log"))
    set_logger_level("urllib3.connectionpool", logging.ERROR)

    init_database()

    try:
        delete_analysis_db(analysis_id)
        delete_analysis_disk(analysis_id)
    except (ResultDoesNotExistError):
        print_info(f"Not found {analysis_id}.")

@click.group(invoke_without_command=True)
@click.option("--cwd", help="Cuckoo Working Directory")
@click.option("-d", "--debug", is_flag=True, help="Enable verbose logging")
@click.pass_context
def main(ctx, cwd, debug):
    if not cwd:
        cwd = cuckoocwd.DEFAULT

    ctx.cwd_path = cwd
    if not cuckoocwd.exists(cwd):
        exit_error(
            f"Cuckoo CWD {cwd} does not yet exist. Run "
            f"'cuckoo createcwd' if this is the first time you are "
            f"running Cuckoo with this CWD path"
        )

    try:
        cuckoocwd.set(cwd)
    except CWDError as e:
        exit_error(f"Failed to set Cuckoo working directory: {e}")

    if debug:
        ctx.loglevel = logging.DEBUG
    else:
        ctx.loglevel = logging.INFO

    if ctx.invoked_subcommand:
        return

@main.command()
@click.argument("days", type=int)
@click.option("--yes", is_flag=True, help="Skip confirmation screen")
@click.pass_context
def remotestorage(ctx, days, yes):
    """Export and deleted finished analyses older than the specified
    amount of days. This requires a remote Cuckoo setup running the API
    and running import mode. The API url and key to use here must be
    configured in the cuckoo.conf.

    \b
    DAYS The age in days of analyses that should be exported
    """

    from cuckoo.common.shutdown import call_registered_shutdowns
    try:
        start_export(days, loglevel=ctx.parent.loglevel, without_confirm=yes)
    except StartupError as e:
        exit_error(e)
    finally:
        call_registered_shutdowns()


@main.command("delete")
@click.argument("state", type=str)
@click.argument("hours", type=int)
@click.option("--yes", is_flag=True, help="Skip confirmation screen")
@click.pass_context
def delete(ctx, state, hours, yes):
    """Delete Waiting manual analyses older than the specified
    amount of hours.

    \b
    STATE  untracked, pending_identification, waiting_manual, pending_pre,
            tasks_pending, no_selected, fatal_error, finished
    HOURS The age in hours of analyses that should be deleted
    """

    try:
        if state == "all":
            delete_analyses("untracked", 0, loglevel=ctx.parent.loglevel, without_confirm=yes)
            delete_analyses("pending_identification", 0, loglevel=ctx.parent.loglevel, without_confirm=yes)
            delete_analyses("waiting_manual", 0, loglevel=ctx.parent.loglevel, without_confirm=yes)
            delete_analyses("pending_pre", 0, loglevel=ctx.parent.loglevel, without_confirm=yes)
            delete_analyses("tasks_pending", 0, loglevel=ctx.parent.loglevel, without_confirm=yes)
            delete_analyses("no_selected", 0, loglevel=ctx.parent.loglevel, without_confirm=yes)
            delete_analyses("fatal_error", 0, loglevel=ctx.parent.loglevel, without_confirm=yes)
            delete_analyses("finished", 0, loglevel=ctx.parent.loglevel, without_confirm=yes)
        else:
            delete_analyses(state, hours, loglevel=ctx.parent.loglevel, without_confirm=yes)
    except StartupError as e:
        exit_error(e)

@main.command("deleteid")
@click.argument("analysis_id", type=str)
@click.pass_context
def deleteid(ctx, analysis_id):
    """Delete specific analysis by ID
    amount of hours.

    \b
    ID id analysis to delete
    """

    try:
        delete_analysis_by_id(analysis_id, loglevel=ctx.parent.loglevel)
    except StartupError as e:
        exit_error(e)
