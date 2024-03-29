/* OMP Command Line Interface
 * $Id$
 * Description: A command line client for the OpenVAS Management Protocol
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 * Michael Wiegand <michael.wiegand@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009, 2010 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @file  omp.c
 * @brief The OMP Command Line Interface
 *
 * This command line tool provides command line arguments
 * corresponding to the OMP protocol commands as well as a
 * direct method to send OMP protocol commands (which is
 * based on XML).
 */

/**
 * \mainpage
 * \section Introduction
 * \verbinclude README
 *
 * \section Installation
 * \verbinclude INSTALL
 *
 * \section copying License Information
 * \verbinclude COPYING
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <glib.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>  /* for tcsetattr */
#include <unistd.h>   /* for getpid */

#include <openvas/misc/openvas_server.h>
#ifdef _WIN32
#include <winsock2.h>
#endif
#ifndef _WIN32
#include <openvas/misc/openvas_logging.h>
#endif
#include <openvas/omp/omp.h>
#include <openvas/omp/xml.h>

/**
 * @brief The name of this program.
 */
#define OMP_PROGNAME "omp"

/**
 * @brief Default Manager (openvasmd) address.
 */
#define OPENVASMD_ADDRESS "127.0.0.1"

/**
 * @brief Default Manager port.
 */
#define OPENVASMD_PORT 9390


/* Connection handling. */

/**
 * @brief Information needed to handle a connection to a server.
 */
typedef struct
{
  gnutls_session_t session;     ///< GnuTLS Session to use.
  int socket;                   ///< Socket to server.
  gchar *username;              ///< Username with which to connect.
  gchar *password;              ///< Password for user with which to connect.
  gchar *host_string;           ///< Server host string.
  gchar *port_string;           ///< Server port string.
  gint port;                    ///< Port of server.
} server_connection_t;

/**
 * @brief Read connection parameters from a key-file.
 *
 * If the key-file could not be loaded, emit warning and return g_malloc0'ed
 * struct. If keys are missing, set the corresponding fields in the struct to
 * 0.
 *
 * @param  conf_file_path  Path to key-file.
 *
 * @return Struct containing the parameters read from key-file (port, host,
 *         user, password).
 */
static server_connection_t *
connection_from_file (const gchar * conf_file_path)
{
  assert (conf_file_path);
  GKeyFile *key_file = g_key_file_new ();
  GError *error = NULL;
  server_connection_t *connection = g_malloc0 (sizeof (*connection));

  /* Load key file. */
  if (g_key_file_load_from_file (key_file, conf_file_path, 0, &error) == FALSE)
    {
      /* Be chatty about non trivial error (file does exist). */
      if (g_file_test (conf_file_path, G_FILE_TEST_EXISTS))
        g_warning ("Could not load connection configuration from %s: %s",
                   conf_file_path, error->message);

      g_error_free (error);
      g_key_file_free (key_file);
      return connection;
    }

#if 0
  /* Check for completeness. */
  if (g_key_file_has_key (key_file, "Connection", "host", &error) == FALSE
      || g_key_file_has_key (key_file, "Connection", "port", &error) == FALSE
      || g_key_file_has_key (key_file, "Connection", "username",
                             &error) == FALSE
      || g_key_file_has_key (key_file, "Connection", "password",
                             &error) == FALSE)
    {
      g_warning ("Connection configuration file misses entrie(s): %s",
                 error->message);
      g_error_free (error);
      return NULL;
    }
#endif

  /* Fill struct if any values found. */
  connection->host_string =
    g_key_file_get_string (key_file, "Connection", "host", NULL);
  connection->port_string =
    g_key_file_get_string (key_file, "Connection", "port", NULL);
  connection->username =
    g_key_file_get_string (key_file, "Connection", "username", NULL);
  connection->password =
    g_key_file_get_string (key_file, "Connection", "password", NULL);

  g_key_file_free (key_file);

  return connection;
}

/** @todo Return on fail. */
/**
 * @brief Connect to an openvas-manager, exiting on failure.
 *
 * Exit with EXIT_FAILURE if connection could not be established or
 * authentication failed, printing a message to stderr.
 *
 * @return TRUE.  Does not return in fail case.
 */
static gboolean
manager_open (server_connection_t * connection)
{
  connection->socket =
    openvas_server_open (&connection->session, connection->host_string,
                         connection->port);

  if (connection->socket == -1)
    {
      fprintf (stderr, "Failed to acquire socket.\n");
      exit (EXIT_FAILURE);
    }

  if (omp_authenticate
      (&connection->session, connection->username, connection->password))
    {
      openvas_server_close (connection->socket, connection->session);
      fprintf (stderr, "Failed to authenticate.\n");
      exit (EXIT_FAILURE);
    }

  return TRUE;
}

/**
 * @brief Closes the connection to a manager.
 *
 * @return 0 on success, -1 on failure.
 */
static int
manager_close (server_connection_t * server)
{
  return openvas_server_close (server->socket, server->session);
}

/**
 * @brief Print tasks.
 *
 * @param[in]  tasks  Tasks.
 *
 * @return 0 success, -1 error.
 */
static int
print_tasks (entities_t tasks)
{
  entity_t task;
  while ((task = first_entity (tasks)))
    {
      if (strcmp (entity_name (task), "task") == 0)
        {
          entity_t entity, report;
          entities_t reports;
          const char *id, *name, *status, *progress;

          id = entity_attribute (task, "id");
          if (id == NULL)
            {
              fprintf (stderr, "Failed to parse task ID.\n");
              return -1;
            }

          entity = entity_child (task, "name");
          if (entity == NULL)
            {
              fprintf (stderr, "Failed to parse task name.\n");
              return -1;
            }
          name = entity_text (entity);

          entity = entity_child (task, "status");
          if (entity == NULL)
            {
              fprintf (stderr, "Failed to parse task status.\n");
              return -1;
            }
          status = entity_text (entity);

          entity = entity_child (task, "progress");
          if (entity == NULL)
            {
              fprintf (stderr, "Failed to parse task progress.\n");
              return -1;
            }
          progress = entity_text (entity);

          printf ("%s  %-7s", id, status);
          if (strcmp (status, "Running") == 0)
            printf (" %2s%%  %s\n", progress, name);
          else
            printf ("      %s\n", name);

          /* Print any reports indented under the task. */

          entity = entity_child (task, "reports");
          if (entity == NULL)
            {
              tasks = next_entities (tasks);
              continue;
            }

          reports = entity->entities;
          while ((report = first_entity (reports)))
            {
              if (strcmp (entity_name (report), "report") == 0)
                {
                  entity_t result_count;
                  const char *id, *status, *holes, *infos, *logs, *warnings;
                  const char *time_stamp;

                  id = entity_attribute (report, "id");
                  if (id == NULL)
                    {
                      fprintf (stderr, "Failed to parse report ID.\n");
                      return -1;
                    }

                  entity = entity_child (report, "scan_run_status");
                  if (entity == NULL)
                    {
                      fprintf (stderr, "Failed to parse report status.\n");
                      return -1;
                    }
                  status = entity_text (entity);

                  result_count = entity_child (report, "result_count");
                  if (result_count == NULL)
                    {
                      fprintf (stderr, "Failed to parse report result_count.\n");
                      return -1;
                    }

                  entity = entity_child (result_count, "hole");
                  if (entity == NULL)
                    {
                      fprintf (stderr, "Failed to parse report hole.\n");
                      return -1;
                    }
                  holes = entity_text (entity);

                  entity = entity_child (result_count, "info");
                  if (entity == NULL)
                    {
                      fprintf (stderr, "Failed to parse report info.\n");
                      return -1;
                    }
                  infos = entity_text (entity);

                  entity = entity_child (result_count, "log");
                  if (entity == NULL)
                    {
                      fprintf (stderr, "Failed to parse report log.\n");
                      return -1;
                    }
                  logs = entity_text (entity);

                  entity = entity_child (result_count, "warning");
                  if (entity == NULL)
                    {
                      fprintf (stderr, "Failed to parse report warning.\n");
                      return -1;
                    }
                  warnings = entity_text (entity);

                  entity = entity_child (report, "timestamp");
                  if (entity == NULL)
                    {
                      fprintf (stderr, "Failed to parse report timestamp.\n");
                      return -1;
                    }
                  time_stamp = entity_text (entity);

                  printf ("  %s  %-7s  %2s  %2s  %2s  %2s  %s\n", id, status,
                          holes, warnings, infos, logs, time_stamp);
                }
              reports = next_entities (reports);
            }
        }
      tasks = next_entities (tasks);
    }
  return 0;
}

/**
 * @brief Print configs.
 *
 * @param[in]  configs  Configs.
 *
 * @return 0 success, -1 error.
 */
static int
print_configs (entities_t configs)
{
  entity_t config;
  while ((config = first_entity (configs)))
    {
      if (strcmp (entity_name (config), "config") == 0)
        {
          entity_t entity;
          const char *id, *name;

          id = entity_attribute (config, "id");
          if (id == NULL)
            {
              fprintf (stderr, "Failed to parse config ID.\n");
              return -1;
            }

          entity = entity_child (config, "name");
          if (entity == NULL)
            {
              fprintf (stderr, "Failed to parse config name.\n");
              return -1;
            }
          name = entity_text (entity);

          printf ("%s  %s\n", id, name);
        }
      configs = next_entities (configs);
    }
  return 0;
}

/**
 * @brief Print targets.
 *
 * @param[in]  targets  Targets.
 *
 * @return 0 success, -1 error.
 */
static int
print_targets (entities_t targets)
{
  entity_t target;
  while ((target = first_entity (targets)))
    {
      if (strcmp (entity_name (target), "target") == 0)
        {
          entity_t entity;
          const char *id, *name;

          id = entity_attribute (target, "id");
          if (id == NULL)
            {
              fprintf (stderr, "Failed to parse target ID.\n");
              return -1;
            }

          entity = entity_child (target, "name");
          if (entity == NULL)
            {
              fprintf (stderr, "Failed to parse target name.\n");
              return -1;
            }
          name = entity_text (entity);

          printf ("%s  %s\n", id, name);
        }
      targets = next_entities (targets);
    }
  return 0;
}

/**
 * @brief Get the list of scan configs.
 *
 * @param[in]  session         Pointer to GNUTLS session.
 * @param[out] status          Status return.  On success contains GET_CONFIGS
 *                             response.
 *
 * @return 0 on success, -1 or OMP response code on error.
 */
int
get_configs (gnutls_session_t* session, entity_t* status)
{
  const char* status_code;
  int ret;

  if (openvas_server_sendf (session, "<get_configs/>") == -1)
    return -1;

  /* Read the response. */

  *status = NULL;
  if (read_entity (session, status)) return -1;

  /* Check the response. */

  status_code = entity_attribute (*status, "status");
  if (status_code == NULL)
    {
      free_entity (*status);
      return -1;
    }
  if (strlen (status_code) == 0)
    {
      free_entity (*status);
      return -1;
    }
  if (status_code[0] == '2') return 0;
  ret = (int) strtol (status_code, NULL, 10);
  free_entity (*status);
  if (errno == ERANGE) return -1;
  return ret;
}



/* Commands. */

/**
 * @brief Performs the OMP get_version command.
 *
 * @param  connection  Connection to manager to use.
 * @param[out] version_str Pointer to the version string.
 *
 * @return 0 success, -1 error.
 */
static int
manager_get_omp_version (server_connection_t * connection, gchar ** version_str)
{
  entity_t entity, version;

  if (openvas_server_send (&(connection->session), "<get_version/>")
      == -1)
    {
      manager_close (connection);
      return -1;
    }

  /* Read the response. */

  entity = NULL;
  if (read_entity (&(connection->session), &entity))
    {
      fprintf (stderr, "Failed to read response.\n");
      manager_close (connection);
      return -1;
    }

  version = entity_child (entity, "version");
  if (version == NULL)
    {
      free_entity (entity);
      fprintf (stderr, "Failed to parse version.\n");
      manager_close (connection);
      return -1;
    }

  *version_str = g_strdup (entity_text(version));

  free_entity (entity);

  return 0;
}

/**
 * @brief Performs the omp get_report command.
 *
 * @param  connection  Connection to manager to use.
 * @param  report_ids  Pointer to task_uuid id.
 * @param  format      Queried report format.
 *
 * @todo This function currently does not use library functions for getting
 * reports to ensure it works with both OMP 1.0 and 2.0. Once OMP 1.0 is
 * retired, this function should use the existing library functions.
 *
 * @return 0 success, -1 error.
 */
static int
manager_get_reports (server_connection_t * connection, gchar ** report_ids,
                     gchar * format)
{
  gchar *version = NULL;
  gchar *default_format = NULL;
  gchar *format_req_str = NULL;

  if (manager_get_omp_version (connection, &version))
    {
      fprintf (stderr, "Failed to determine OMP version.\n");
      manager_close (connection);
      return -1;
    }

  if (strcmp (version, "1.0") == 0)
    {
      default_format = "XML";
      format_req_str = "format";
    }
  else if (strcmp (version, "2.0") == 0)
    {
      default_format = "d5da9f67-8551-4e51-807b-b6a873d70e34";
      format_req_str = "format_id";
    }
  else
    {
      default_format = "a994b278-1f62-11e1-96ac-406186ea4fc5";
      format_req_str = "format_id";
    }

  g_free (version);

  if (format == NULL || strcasecmp (format, default_format) == 0)
    {
      entity_t entity, report_xml;

      if (openvas_server_sendf (&(connection->session),
                                "<get_reports"
                                " result_hosts_only=\"0\""
                                " first_result=\"0\""
                                " sort_field=\"ROWID\""
                                " sort_order=\"1\""
                                " %s=\"%s\""
                                " report_id=\"%s\"/>",
                                format_req_str,
                                format ? format :
                                default_format,
                                *report_ids))
        {
          fprintf (stderr, "Failed to get report.\n");
          manager_close (connection);
          return -1;
        }

      if (read_entity (&connection->session, &entity)) {
        fprintf (stderr, "Failed to get report.\n");
        manager_close (connection);
        return -1;
      }

      report_xml = entity_child (entity, "report");
      if (report_xml == NULL)
        {
          free_entity (entity);
          fprintf (stderr, "Failed to get report.\n");
          manager_close (connection);
          return -1;
        }

      print_entity (stdout, report_xml);
    }
  else
    {
      guchar *report = NULL;
      gsize report_size = 0;
      char first;
      const char* status;
      entity_t entity;

      if (openvas_server_sendf (&(connection->session),
                                "<get_reports %s=\"%s\" report_id=\"%s\"/>",
                                format_req_str,
                                format,
                                *report_ids))
        {
          fprintf (stderr, "Failed to get report.\n");
          manager_close (connection);
          return -1;
        }

      /* Read the response. */

      entity = NULL;
      if (read_entity (&connection->session, &entity))
        {
          fprintf (stderr, "Failed to get report.\n");
          manager_close (connection);
          return -1;
        }

      /* Check the response. */

      status = entity_attribute (entity, "status");
      if (status == NULL)
        {
          free_entity (entity);
          fprintf (stderr, "Failed to get report.\n");
          manager_close (connection);
          return -1;
        }
      if (strlen (status) == 0)
        {
          free_entity (entity);
          fprintf (stderr, "Failed to get report.\n");
          manager_close (connection);
          return -1;
        }
      first = status[0];
      if (first == '2')
        {
          const char* report_64;
          entity_t report_xml;

          report_xml = entity_child (entity, "report");
          if (report_xml == NULL)
            {
              free_entity (entity);
              fprintf (stderr, "Failed to get report.\n");
              manager_close (connection);
              return -1;
            }

          report_64 = entity_text (report_xml);
          if (strlen (report_64) == 0)
            {
              report = (guchar *) g_strdup ("");
              report_size = 0;
            }
          else
            {
              report = g_base64_decode (report_64, &report_size);
            }

          free_entity (entity);
        }
      else
        {
          free_entity (entity);
          fprintf (stderr, "Failed to get report.\n");
          manager_close (connection);
          return -1;
        }

      if (fwrite (report, 1, report_size, stdout) < report_size)
        {
          fprintf (stderr, "Failed to write entire report.\n");
          manager_close (connection);
          return -1;
        }
    }

  return 0;
}

/**
 * @brief Performs the OMP get_report_formats command.
 *
 * @param  connection  Connection to manager to use.
 *
 * @return 0 success, -1 error.
 */
static int
manager_get_report_formats (server_connection_t * connection)
{
  entity_t entity, format;
  entities_t formats;

  if (openvas_server_send (&(connection->session), "<get_report_formats/>")
      == -1)
    {
      manager_close (connection);
      return -1;
    }

  /* Read the response. */

  entity = NULL;
  if (read_entity (&(connection->session), &entity))
    {
      fprintf (stderr, "Failed to read response.\n");
      manager_close (connection);
      return -1;
    }

  formats = entity->entities;
  while ((format = first_entity (formats)))
    {
      if (strcmp (entity_name (format), "report_format") == 0)
        {
          const char *id;
          entity_t name;

          id = entity_attribute (format, "id");
          if (id == NULL)
            {
              free_entity (entity);
              fprintf (stderr, "Failed to parse report format ID.\n");
              manager_close (connection);
              return -1;
            }

          name = entity_child (format, "name");
          if (name == NULL)
            {
              free_entity (entity);
              fprintf (stderr, "Failed to parse report format name.\n");
              manager_close (connection);
              return -1;
            }

          printf ("%s  %s\n", id, entity_text (name));
        }
      formats = next_entities (formats);
    }

  free_entity (entity);

  return 0;
}

/**
 * @brief Reads an entire line from a stream, suppressing character output.
 *
 * @param[out]  lineptr  Location of the buffer where the line is stored.
 * @param[out]  n  Size of allocated buffer in lineptr is not null.
 * @param[in] stream  Stream from which the line should be read.
 *
 * This function mimics the behaviour of getline (). Please see the man page of
 * getline () for additional information about the parameters. This function was
 * taken from the example provided in the GNU C Library, for example at
 * http://www.gnu.org/s/libc/manual/html_node/getpass.html.
 *
 * @todo Move this function to openvas-libraries since openvas-administrator
 * uses it as well.
 */
ssize_t
read_password (char **lineptr, size_t *n, FILE *stream)
{
  struct termios old, new;
  int nread;

  /* Turn echoing off and fail if we can't. */
  if (tcgetattr (fileno (stream), &old) != 0)
    return -1;
  new = old;
  new.c_lflag &= ~ECHO;
  if (tcsetattr (fileno (stream), TCSAFLUSH, &new) != 0)
    return -1;

  /* Read the password. */
  nread = getline (lineptr, n, stream);

  /* Restore terminal. */
  (void) tcsetattr (fileno (stream), TCSAFLUSH, &old);

  return nread;
}


/**
 * @brief GNUTLS log handler
 */
static void
my_gnutls_log_func (int level, const char *text)
{
  fprintf (stderr, "[%d] (%d) %s", getpid (), level, text);
  if (*text && text[strlen (text) -1] != '\n')
    putc ('\n', stderr);
}



/* Entry point. */

int
main (int argc, char **argv)
{
  server_connection_t *connection = NULL;
  /* The return status of the command. */
  int exit_status = -1;

  /* Global options. */
  static gboolean prompt = FALSE;
  static gboolean print_version = FALSE;
  static gboolean be_verbose = FALSE;
  static gchar *conf_file_path = NULL;
  static gchar *manager_host_string = NULL;
  static gchar *manager_port_string = NULL;
  static gchar *omp_username = NULL;
  static gchar *omp_password = NULL;
  /* Shared command options. */
  static gchar *name = NULL;
  /* Command create-task. */
  static gboolean cmd_create_task = FALSE;
  static gchar *comment = NULL;
  static gchar *config = NULL;
  static gboolean rc = FALSE;
  static gchar *target = NULL;
  /* Command delete-report. */
  static gboolean cmd_delete_report = FALSE;
  /* Command delete-task. */
  static gboolean cmd_delete_task = FALSE;
  /* Command get-report. */
  static gboolean cmd_get_report = FALSE;
  /* Command get-report-formats. */
  static gboolean cmd_get_report_formats = FALSE;
  /* Command get-omp-version. */
  static gboolean cmd_get_omp_version = FALSE;
  static gchar *format = NULL;
  /* Command get-tasks. */
  static gboolean cmd_get_tasks = FALSE;
  /* Command get-configs. */
  static gboolean cmd_get_configs = FALSE;
  /* Command get-targets. */
  static gboolean cmd_get_targets = FALSE;
  /* Command modify-task. */
  static gboolean cmd_modify_task = FALSE;
  static gboolean file = FALSE;
  /* Command start-task. */
  static gboolean cmd_start_task = FALSE;
  /* Command given as XML. */
  static gchar *cmd_xml = NULL;
  /* The rest of the args. */
  static gchar **rest = NULL;
  /* Pretty print option. */
  static gboolean pretty_print = FALSE;

  GError *error = NULL;

  GOptionContext *option_context;
  static GOptionEntry option_entries[] = {
    /* Global options. */
    {"host", 'h', 0, G_OPTION_ARG_STRING, &manager_host_string,
     "Connect to manager on host <host>", "<host>"},
    {"port", 'p', 0, G_OPTION_ARG_STRING, &manager_port_string,
     "Use port number <number>", "<number>"},
    {"version", 'V', 0, G_OPTION_ARG_NONE, &print_version,
     "Print version.", NULL},
    {"verbose", 'v', 0, G_OPTION_ARG_NONE, &be_verbose,
     "Verbose messages (WARNING: may reveal passwords).", NULL},
    {"username", 'u', 0, G_OPTION_ARG_STRING, &omp_username,
     "OMP username", "<username>"},
    {"password", 'w', 0, G_OPTION_ARG_STRING, &omp_password,
     "OMP password", "<password>"},
    {"config-file", 0, 0, G_OPTION_ARG_FILENAME, &conf_file_path,
     "Configuration file for connection parameters.", "<config-file>"},
    {"prompt", 'P', 0, G_OPTION_ARG_NONE, &prompt,
     "Prompt to exit.", NULL},
    {"get-omp-version", 'O', 0, G_OPTION_ARG_NONE, &cmd_get_omp_version,
     "Print OMP version.", NULL},
    /* Shared command options. */
    {"name", 'n', 0, G_OPTION_ARG_STRING, &name,
     "Name for create-task.",
     "<name>"},
    /* Command create-task. */
    {"create-task", 'C', 0, G_OPTION_ARG_NONE, &cmd_create_task,
     "Create a task.", NULL},
    {"comment", 'm', 0, G_OPTION_ARG_STRING, &comment,
     "Comment for create-task.",
     "<name>"},
    {"config", 'c', 0, G_OPTION_ARG_STRING, &config,
     "Config for create-task.",
     "<config>"},
    {"rc", 'r', 0, G_OPTION_ARG_NONE, &rc,
     "Create task with RC read from stdin.", NULL},
    {"target", 't', 0, G_OPTION_ARG_STRING, &target,
     "Target for create-task.",
     "<target>"},
    /* Command delete-report. */
    {"delete-report", 'E', 0, G_OPTION_ARG_NONE, &cmd_delete_report,
     "Delete one or more reports.", NULL},
    /* Command delete-task. */
    {"delete-task", 'D', 0, G_OPTION_ARG_NONE, &cmd_delete_task,
     "Delete one or more tasks.", NULL},
    /* Command get-report. */
    {"get-report", 'R', 0, G_OPTION_ARG_NONE, &cmd_get_report,
     "Get report of one task.", NULL},
    {"get-report-formats", 'F', 0, G_OPTION_ARG_NONE, &cmd_get_report_formats,
     "Get report formats. (OMP 2.0 only)", NULL},
    {"format", 'f', 0, G_OPTION_ARG_STRING, &format,
     "Format for get-report.",
     "<format>"},
    /* Command get-tasks. */
    {"get-tasks", 'G', 0, G_OPTION_ARG_NONE, &cmd_get_tasks,
     "Get status of one, many or all tasks.", NULL},
    /* Command get-configs. */
    {"get-configs", 'g', 0, G_OPTION_ARG_NONE, &cmd_get_configs,
     "Get configs.", NULL},
    /* Command get-targets. */
    {"get-targets", 'T', 0, G_OPTION_ARG_NONE, &cmd_get_targets,
     "Get targets.", NULL},
    /* Pretty printing for "direct" xml (in combination with -X). */
    {"pretty-print", 'i', 0, G_OPTION_ARG_NONE, &pretty_print,
     "In combination with -X, pretty print the response.", NULL},
    /* Command start-task. */
    {"start-task", 'S', 0, G_OPTION_ARG_NONE, &cmd_start_task,
     "Start one or more tasks.", NULL},
    /* Command modify-task. */
    {"modify-task", 'M', 0, G_OPTION_ARG_NONE, &cmd_modify_task,
     "Modify a task.", NULL},
    {"file", 0, 0, G_OPTION_ARG_NONE, &file,
     "Add text in stdin as file on task.", NULL},
    /* Command as XML. */
    {"xml", 'X', 0, G_OPTION_ARG_STRING, &cmd_xml,
     "XML command (e.g. \"<help/>\"\").  \"-\" to read from stdin.",
     "<command>"},
    {G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_STRING_ARRAY, &rest,
     NULL, NULL},
    {NULL}
  };

  if (setlocale (LC_ALL, "") == NULL)
    {
      printf ("Failed to setlocale\n\n");
      exit (EXIT_FAILURE);
    }

  option_context =
    g_option_context_new ("- OpenVAS OMP Command Line Interface");
  g_option_context_add_main_entries (option_context, option_entries, NULL);
  if (!g_option_context_parse (option_context, &argc, &argv, &error))
    {
      printf ("%s\n\n", error->message);
      exit (EXIT_FAILURE);
    }

  if (print_version)
    {
      printf ("OMP Command Line Interface %s\n", OPENVASCLI_VERSION);
      printf ("Copyright (C) 2010-2013 Greenbone Networks GmbH\n");
      printf ("License GPLv2+: GNU GPL version 2 or later\n");
      printf
        ("This is free software: you are free to change and redistribute it.\n"
         "There is NO WARRANTY, to the extent permitted by law.\n\n");
      exit (EXIT_SUCCESS);
    }

  /* Check that one and at most one command option is present. */
  {
    int commands;
    commands =
      (int) cmd_create_task + (int) cmd_delete_report + (int) cmd_delete_task +
      (int) cmd_get_report + (int) cmd_get_report_formats +
      (int) cmd_get_tasks + (int) cmd_modify_task + (int) cmd_start_task +
      (int) cmd_get_targets + (int) cmd_get_omp_version + (int) cmd_get_configs +
      (int) (cmd_xml != NULL);
    if (commands == 0)
      {
        fprintf (stderr, "One command option must be present.\n");
        exit (EXIT_FAILURE);
      }
    if (commands > 1)
      {
        fprintf (stderr, "Only one command option must be present.\n");
        exit (EXIT_FAILURE);
      }
  }

  /* Setup the connection structure from the arguments and conf file.
   * Precedence of values is the following:
   * 1) command line argument (e.g. --port) 2) conf file 3) default */

  if (conf_file_path == NULL)
    conf_file_path = g_build_filename (g_get_home_dir (), "omp.config", NULL);
  connection = connection_from_file (conf_file_path);
  g_free (conf_file_path);

  if (manager_host_string != NULL)
    connection->host_string = manager_host_string;
  else if (connection->host_string == NULL)
    connection->host_string = OPENVASMD_ADDRESS;

  if (manager_port_string != NULL)
    connection->port = atoi (manager_port_string);
  else if (connection->port_string != NULL)
    connection->port = atoi (connection->port_string);
  else
    connection->port = OPENVASMD_PORT;

  if (connection->port <= 0 || connection->port >= 65536)
    {
      fprintf (stderr, "Manager port must be a number between 0 and 65536.\n");
      exit (EXIT_FAILURE);
    }

  if (omp_username != NULL)
    connection->username = omp_username;
  else if (connection->username == NULL)
    connection->username = g_strdup (g_get_user_name ());

  if (omp_password != NULL)
    connection->password = omp_password;
  else if (connection->password == NULL)
    {
      gchar *pw = NULL;
      size_t n;

      printf ("Enter password: ");
      int ret = read_password (&pw, &n, stdin);
      printf ("\n");

      if (ret < 0)
        {
          fprintf (stderr, "Failed to read password from console!\n");
          exit (EXIT_FAILURE);
        }

      /* Remove the trailing newline character. */
      pw[ret - 1] = '\0';

      if (strlen (pw) > 0)
        connection->password = pw;
      else
        {
          fprintf (stderr, "Password must be set.\n");
          exit (EXIT_FAILURE);
        }
    }

  if (be_verbose)
    {
      const char *s;

      /** @todo Other modules ship with log level set to warning. */
      printf ("\nWARNING: Verbose mode may reveal passwords!\n\n");
      printf ("Will try to connect to host %s, port %d...\n",
              connection->host_string, connection->port);

      /* Enable GNUTLS debugging if the envvar, as used by the
         standard log functions, is set.  */
      if ((s=getenv ("OPENVAS_GNUTLS_DEBUG")))
        {
          gnutls_global_set_log_function (my_gnutls_log_func);
          gnutls_global_set_log_level (atoi (s));
        }
    }
  else
    {
#ifndef _WIN32
      g_log_set_default_handler (openvas_log_silent, NULL);
#endif
    }

  /* Run the single command. */

  if (cmd_create_task)
    {
      char *id = NULL;

      if (rc && (config || target))
        {
          fprintf (stderr, "create-task rc given with config or target.\n");
          exit (EXIT_FAILURE);
        }

      manager_open (connection);

      if (rc)
        {
          gchar *content;
          gsize content_len;
          GIOChannel *stdin_channel;

          /* Mixing stream and file descriptor IO might lead to trouble. */
          error = NULL;
          stdin_channel = g_io_channel_unix_new (fileno (stdin));
          g_io_channel_read_to_end (stdin_channel, &content, &content_len,
                                    &error);
          g_io_channel_shutdown (stdin_channel, TRUE, NULL);
          g_io_channel_unref (stdin_channel);
          if (error)
            {
              fprintf (stderr, "failed to read from stdin: %s\n",
                       error->message);
              g_error_free (error);
              exit (EXIT_FAILURE);
            }

          if (omp_create_task_rc
              (&(connection->session), content, content_len,
               name ? name : "unnamed task", comment ? comment : "", &id))
            {
              g_free (content);
              fprintf (stderr, "Failed to create task.\n");
              manager_close (connection);
              exit (EXIT_FAILURE);
            }
        }
      else
        {
          if (omp_create_task
              (&(connection->session), name ? name : "unnamed task",
               config ? config : "Full and fast", target ? target : "Localhost",
               comment ? comment : "", &id))
            {
              fprintf (stderr, "Failed to create task.\n");
              manager_close (connection);
              exit (EXIT_FAILURE);
            }
        }

      printf ("%s", id);
      putchar ('\n');

      manager_close (connection);
      exit_status = 0;
    }
  else if (cmd_delete_report)
    {
      gchar **point = rest;

      if (point == NULL || *point == NULL)
        {
          fprintf (stderr, "delete-report requires at least one argument.\n");
          exit (EXIT_FAILURE);
        }

      manager_open (connection);

      while (*point)
        {
          if (omp_delete_report (&(connection->session), *point))
            {
              fprintf (stderr, "Failed to delete report %s, exiting.\n",
                       *point);
              manager_close (connection);
              exit (EXIT_FAILURE);
            }
          point++;
        }

      manager_close (connection);
      exit_status = 0;
    }
  else if (cmd_delete_task)
    {
      gchar **point = rest;

      if (point == NULL || *point == NULL)
        {
          fprintf (stderr, "delete-task requires at least one argument.\n");
          exit (EXIT_FAILURE);
        }

      manager_open (connection);

      while (*point)
        {
          if (omp_delete_task (&(connection->session), *point))
            {
              fprintf (stderr, "Failed to delete task.\n");
              manager_close (connection);
              exit (EXIT_FAILURE);
            }
          point++;
        }

      manager_close (connection);
      exit_status = 0;
    }
  else if (cmd_get_tasks)
    {
      gchar **point = rest;
      entity_t status;

      manager_open (connection);

      if (point)
        while (*point)
          {
            omp_get_task_opts_t opts;

            opts = omp_get_task_opts_defaults;
            opts.task_id = *point;
            opts.details = 1;
            opts.rcfile = 0;
            opts.actions = "g";

            if (omp_get_task_ext (&(connection->session), opts, &status))
              {
                fprintf (stderr, "Failed to get status of task %s.\n", *point);
                manager_close (connection);
                exit (EXIT_FAILURE);
              }
            else
              {
                if (print_tasks (status->entities))
                  {
                    manager_close (connection);
                    exit (EXIT_FAILURE);
                  }
              }

            point++;
          }
      else
        {
          omp_get_tasks_opts_t opts;

          opts = omp_get_tasks_opts_defaults;
          opts.details = 0;
          opts.rcfile = 0;
          opts.actions = "g";

          if (omp_get_tasks_ext (&(connection->session), opts, &status))
            {
              fprintf (stderr, "Failed to get status of all tasks.\n");
              manager_close (connection);
              exit (EXIT_FAILURE);
            }
          if (print_tasks (status->entities))
            {
              manager_close (connection);
              exit (EXIT_FAILURE);
            }
        }

      manager_close (connection);
      exit_status = 0;
    }
  else if (cmd_get_configs)
    {
      entity_t status;

      manager_open (connection);

      if (get_configs (&(connection->session), &status))
        {
          fprintf (stderr, "Failed to get configs.\n");
          exit (EXIT_FAILURE);
        }
      if (print_configs (status->entities))
        {
          manager_close (connection);
          exit (EXIT_FAILURE);
        }

      manager_close (connection);
      exit_status = 0;
    }
  else if (cmd_get_targets)
    {
      entity_t status;

      manager_open (connection);

      if (omp_get_targets (&(connection->session), NULL, 0, 0, &status))
        {
          fprintf (stderr, "Failed to get targets.\n");
          exit (EXIT_FAILURE);
        }
      if (print_targets (status->entities))
        {
          manager_close (connection);
          exit (EXIT_FAILURE);
        }

      manager_close (connection);
      exit_status = 0;
    }
  else if (cmd_get_report)
    {
      gchar **report_ids = rest;

      if (report_ids == NULL || *report_ids == NULL)
        {
          fprintf (stderr, "get-report requires one argument.\n");
          exit (EXIT_FAILURE);
        }

      manager_open (connection);
      exit_status = manager_get_reports (connection, report_ids, format);
      if (exit_status == 0)
        manager_close (connection);
    }
  else if (cmd_get_report_formats)
    {
      manager_open (connection);
      exit_status = manager_get_report_formats (connection);
      if (exit_status == 0)
        manager_close (connection);
    }
  else if (cmd_get_omp_version)
    {
      gchar *version = NULL;
      manager_open (connection);
      exit_status = manager_get_omp_version (connection, &version);
      printf ("Version: %s\n", version);
      if (exit_status == 0)
        manager_close (connection);
    }
  else if (cmd_modify_task)
    {
      gchar **point = rest;
      gchar *content;
      gsize content_len;
      GIOChannel *stdin_channel;

      if (point == NULL || *point == NULL)
        {
          fprintf (stderr, "modify-task requires one argument.\n");
          exit (EXIT_FAILURE);
        }

      if (name == NULL)
        {
          fprintf (stderr,
                   "modify-task requires the name option (path to file).\n");
          exit (EXIT_FAILURE);
        }

      if (file == FALSE)
        {
          fprintf (stderr, "modify-task requires the file option.\n");
          exit (EXIT_FAILURE);
        }

      if (file)
        {
          manager_open (connection);

          /* Mixing stream and file descriptor IO might lead to trouble. */
          error = NULL;
          stdin_channel = g_io_channel_unix_new (fileno (stdin));
          g_io_channel_read_to_end (stdin_channel, &content, &content_len,
                                    &error);
          g_io_channel_shutdown (stdin_channel, TRUE, NULL);
          g_io_channel_unref (stdin_channel);
          if (error)
            {
              fprintf (stderr, "failed to read from stdin: %s\n",
                       error->message);
              g_error_free (error);
              exit (EXIT_FAILURE);
            }

#if 0
          /** todo As in get-report, this is how the commands will work. */
          exit_status =
            manager_modify_task_file (connection, *point, name, content,
                                      content_len, error);
#else
          if (omp_modify_task_file
              (&(connection->session), *point, name, content, content_len))
            {
              g_free (content);
              fprintf (stderr, "Failed to modify task.\n");
              manager_close (connection);
              exit (EXIT_FAILURE);
            }

          manager_close (connection);
          exit_status = 0;
#endif
        }
    }
  else if (cmd_start_task)
    {
      gchar **point = rest;

      if (point == NULL || *point == NULL)
        {
          fprintf (stderr, "start-task requires at least one argument.\n");
          exit (EXIT_FAILURE);
        }

      manager_open (connection);

      while (*point)
        {
          char *report_id;
          if (omp_start_task_report
              (&(connection->session), *point, &report_id))
            {
              fprintf (stderr, "Failed to start task.\n");
              manager_close (connection);
              exit (EXIT_FAILURE);
            }
          printf ("%s\n", report_id);
          free (report_id);
          point++;
        }
      exit_status = 0;

      manager_close (connection);
    }
  else if (cmd_xml)
    {
      manager_open (connection);

      /** @todo Move to connection_t and manager_open. */
      if (prompt)
        {
          fprintf (stderr, "Connected, press a key to continue.\n");
          getchar ();
        }

      if (strcmp (cmd_xml, "-") == 0)
        {
          GError *error;
          gchar *content;
          gsize content_len;
          GIOChannel *stdin_channel;

          /* Mixing stream and file descriptor IO might lead to trouble. */
          error = NULL;
          stdin_channel = g_io_channel_unix_new (fileno (stdin));
          g_io_channel_read_to_end (stdin_channel, &content, &content_len,
                                    &error);
          g_io_channel_shutdown (stdin_channel, TRUE, NULL);
          g_io_channel_unref (stdin_channel);
          if (error)
            {
              fprintf (stderr, "Failed to read from stdin: %s\n",
                       error->message);
              g_error_free (error);
              exit (EXIT_FAILURE);
            }

          g_free (cmd_xml);
          cmd_xml = content;
        }

      if (be_verbose)
        printf ("Sending to manager: %s\n", cmd_xml);

      if (openvas_server_send (&(connection->session), cmd_xml) == -1)
        {
          manager_close (connection);
          fprintf (stderr, "Failed to send_to_manager.\n");
          exit (EXIT_FAILURE);
        }

      /* Read the response. */

      entity_t entity = NULL;
      if (read_entity (&(connection->session), &entity))
        {
          fprintf (stderr, "Failed to read response.\n");
          manager_close (connection);
          exit (EXIT_FAILURE);
        }

      if (be_verbose)
        printf ("Got response:\n");
      if (pretty_print == FALSE)
        print_entity (stdout, entity);
      else
        print_entity_format (entity, GINT_TO_POINTER (2));
      printf ("\n");

      /* Cleanup. */

      /** @todo Move to connection_t and manager_open. */
      if (prompt)
        {
          fprintf (stderr, "Press a key when done.\n");
          getchar ();
        }

      manager_close (connection);
      free_entity (entity);

      exit_status = 0;
    }
  else
    /* The option processing ensures that at least one command is present. */
    assert (0);

  /* Exit. */

  if (be_verbose)
    {
      if (exit_status)
        printf ("Command failed.\n");
      else
        printf ("Command completed successfully.\n");
    }

  exit (exit_status);
}
