<?php
/**
 * 
 */

define('EAS_DEBUG', true);


if (EAS_DEBUG):
  error_reporting(E_ALL);
  ini_set('display_errors', 'on');
  ini_set("log_errors", 1);
  ini_set("error_log", "php-error.log");
endif;


class epohs_Anti_Spam {

  private $class_dir = false;
  public  $self_url = null;
  private $cfg = false;
  private $cfg_err = null;
  private $db = false;
  private $cur_timestamp = null;

  private $attempt_flag_lvl = 0;



  public function __construct() {

    $this->class_dir = __DIR__;

    $this->self_url = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";

    $this->cur_timestamp = time();

    // Make sure a config file exists.
    // If not, bail with an error message.
    if ( $this->get_config() !== true ):


      switch ( $this->cfg_err ):
        case -1:
          $this->respond(array('status' => -1, 'msg' => 'Could not find a config file.'));
          break;
        case -2:
          $this->respond(array('status' => -2, 'msg' => 'Malformed config file.'));
          break;
        case -3:
          $this->respond(array('status' => -3, 'msg' => 'Missing requirement in config.'));
          break;
        case -4:
          $this->respond(array('status' => -4, 'msg' => 'Config file needs setup.'));
          break;
        
        default:
          $this->respond(array('status' => -666, 'msg' => 'Config file generic error. ERR:(' . var_export( $this->cfg_err, true) . ') CONF:(' . var_export( $this->get_config(), true) . ')' ));
          break;
      endswitch;

      die();


    endif;



    if ( $this->config_var('use_database') && $this->config_var(['dirs', 'database']) ):

      $this->set_db_conn();

    endif;



    // This MUST happen *before* any HTML
    // is output to the page.
    if ( $this->config_var(['tests', 'supports', 'cookie']) ):

      $this->init_cookie();

    endif;







  } // __construct()




  /**
  *
  *
  */
  public function init_form( $args = false ) {

    if ( $this->config_var(['tests', 'supports', 'javascript']) ):

      echo '<script type="text/javascript" src="' . $this->self_url . $this->config_var(['dirs', 'javascript']) . '/anti-spam.js"></script>' . PHP_EOL;

      $this->init_javascript();

    endif;

    // Inject CSS
    echo '<link rel="stylesheet" type="text/css" href = "' . $this->self_url . $this->config_var(['dirs', 'css']) . '/anti-spam.css" />' . PHP_EOL;



    if ( $this->config_var('use_database') ):

      $visitor_ip = $this->get_client_ip();
      $form_nonce = hash('crc32b', ($visitor_ip . $this->cur_time()));

      $field_args = array(
                      'type' => 'hidden',
                      'name' => $this->config_var('form_id_name'),
                      'value' => $form_nonce
                    );

      if (EAS_DEBUG):
        $field_args['extra'] = array('data-visitor-ip' => $visitor_ip);
      endif;


      // We do not want to overwrite our stored
      // form nonce if we are testing a submitted form.
      if ( !$this->get_form_nonce() ):

        $this->insert_form_nonce($form_nonce, $visitor_ip);

      endif;

      
      // Write a hidden field containing our unique form ID
      $this->form_field($field_args);

    endif;




    if ( $this->config_var(['tests', 'honeypot']) ):

      $this->init_honeypot();

    endif;


    if ( $this->config_var(['tests', 'timestamp']) ):

      $this->init_timestamp();

    endif;



  } // init_form()







  /**
  *
  *
  */
  public function check_form( $args = false ) {


    if ( $this->config_var(['tests', 'honeypot']) ):

      $this->check_honeypot();

    endif;



    if ( $this->config_var(['tests', 'timestamp']) ):

      $this->check_timestamp();

    endif;



    if ( $this->config_var(['tests', 'supports', 'javascript']) ):

      $this->check_javascript();

    endif;



    if ( $this->config_var(['tests', 'supports', 'cookie']) ):

      $this->check_cookie();

    endif;

  } // check_form()







  /**
   * 
   * 
   */
  private function init_honeypot() {

    // Required (filled) Honeypot
    $this->form_field(array(
              'label' => 'Do not change this:',
              'name' => $this->config_var(['tests', 'honeypot_vals', 'pos_name']),
              'value' => $this->config_var(['tests', 'honeypot_vals', 'pos_val']),
              'wrap' => array(
                            'extra' => array('data-' . $this->config_var('noshow_data_name') => 'true')
                          )
            ));
    
    
    // Required (empty) Honeypot
    $this->form_field(array(
              'label' => 'Leave this empty:',
              'name' => $this->config_var(['tests', 'honeypot_vals', 'neg_name']),
              'value' => $this->config_var(['tests', 'honeypot_vals', 'neg_val']),
              'wrap' => array(
                            'extra' => array('data-' . $this->config_var('noshow_data_name') => 'true')
                          )
            ));

  } // init_honeypot()






  /**
   * 
   * 
   */
  private function check_honeypot() {

    $positive_name = $this->config_var(['tests', 'honeypot_vals', 'pos_name']);
    $negative_name = $this->config_var(['tests', 'honeypot_vals', 'neg_name']);

    $positive_val = ( isset($_POST[$positive_name]) ) ? trim($_POST[$positive_name]) : false;
    $negative_val = ( isset($_POST[$negative_name]) ) ? trim($_POST[$negative_name]) : false;


    if ( $positive_val === false || $negative_val === false ):

      echo 'missing honeypots';
      return -100;

    endif;


    if ( $positive_val != $this->config_var(['tests', 'honeypot_vals', 'pos_val']) ):

      echo 'Bad positive honeypot';
      return -105;

    endif;


    if ( $negative_val != "" ):

      echo 'Bad negative honeypot';
      return -110;

    endif;

    
    return true;

  } // check_honeypot()








  /**
  *
  *
  */
  public function init_timestamp() {

    $field_args = array(
                    'type' => 'hidden',
                    'name' => 'secret_token'
                  );


    if ( $this->config_var(['tests', 'supports', 'javascript']) ):

      $field_args['value'] = hash('crc32b', $this->cur_time());
      $field_args['extra'] = array('data-ts' => $this->cur_time());

    else:

      $field_args['value'] = $this->cur_time();

    endif;


    // Create a hidden field to hold a timestamp value
    $this->form_field($field_args);


  } // init_form()





  /**
   * 
   * 
   */
  private function check_timestamp($ts = false) {

    if ($ts):
      
    else:
      $posted_timestamp_val = ( isset($_POST['secret_token']) ) ? trim($_POST['secret_token']) : false;
    endif;


    // Empty timestamp
    if ( $posted_timestamp_val == false ):

      echo 'Empty timestamp';
      return -200;

    endif;


    // Invalid timestamp
    if ( !$this->is_valid_timestamp($posted_timestamp_val)  ):

      echo 'Invalid timestamp (' . var_export($posted_timestamp_val, true) . ')';
      return -205;

    endif;


    // Timestamp too old
    if ( $this->config_var(['tests', 'timestamp_details', 'test_too_old']) ):

      if ( ($posted_timestamp_val - $this->cur_time()) > $this->config_var(['tests', 'timestamp_details', 'fail_older_than']) ):

        echo 'Timestamp too old';
        return -210;

      endif;

    endif;


    // Timestamp too new
    if ( $this->config_var(['tests', 'timestamp_details', 'test_too_new']) ):

      if ( ($this->cur_time() - $posted_timestamp_val) < $this->config_var(['tests', 'timestamp_details', 'fail_newer_than']) ):

        echo 'Timestamp too new: ' . var_export(($posted_timestamp_val - $this->cur_time()), true);
        return -215;

      endif;

    endif;
    
    return true;

  } // check_timestamp()







  /**
  *
  *
  */
  public function init_javascript() {

    $js_commands = array();

    //
    if ( $this->config_var(['tests', 'timestamp']) ):

      $js_commands[] = 'eas.abc.z(eas.abc.a);';

    else:

      $js_commands[] = 'eas.abc.z(eas.abc.b);';

    endif;


    if ( !empty($js_commands) ):

      ?>
      <script type="text/javascript">
      //<![CDATA[
      <?= join(PHP_EOL, $js_commands) . PHP_EOL; ?>
      //]]>
      </script>
      <?

    endif;


  } // init_javascript()








  /**
  *
  *
  */
  public function check_javascript() {

    if ( !$this->config_var(['tests', 'timestamp']) ):

      $posted_jschk_val = ( isset($_POST[$this->config_var(['tests', 'js_chk_details', 'input_name'])]) ) ? trim($_POST[$this->config_var(['tests', 'js_chk_details', 'input_name'])]) : false;

      if ( $posted_jschk_val != $this->config_var(['tests', 'js_chk_details', 'input_val']) ):

        echo 'Bad JS val: ' . var_export($posted_jschk_val, true);
        return -300;

      endif;

    endif;

    return true;

  } // init_javascript_check()






  /**
  *
  *
  */
  public function init_cookie() {


    //
    if ( !$this->config_var(['tests', 'javascript']) ):

      $c_name = $this->config_var(['tests', 'cookie_details', 'name']);
      $c_val = ($this->config_var(['tests', 'timestamp'])) ? $this->cur_time() : $this->config_var(['tests', 'cookie_details', 'val']);
      $c_exp = $this->config_var(['tests', 'cookie_details', 'expires']);

      setcookie($c_name, $c_val, time() + $c_exp);
      
    endif;



  } // init_cookie()





  /**
  *
  *
  */
  public function check_cookie() {

    $cookie_name = $this->config_var(['tests', 'cookie_details', 'name']);

    $this->log('c_name: ' . var_export($cookie_name, true) . __LINE__);

    // First, make sure there was a cookie passed
    if ( isset($_COOKIE[$cookie_name]) ):

      $check_timestamp = ($this->config_var(['tests', 'timestamp'])) ? true : false;
      $passed_val = $_COOKIE[$cookie_name];


      if ($check_timestamp):

        $this->log('passed val: ' . var_export($passed_val, true) . __LINE__);

        // Check the timestamp validity
        $is_ts_good = $this->check_javascript($passed_val);


        if ( $is_ts_good ):

          // If we're using a database, we can
          // check to ensure that not only is
          // the timestamp a valid timestamp, but
          // that is is the actual timestamp we
          // assigned to the original form.
          if ( $this->config_var('use_database') ):

            $passed_form_id = $this->get_form_nonce();
            $db_nonce = $this->get_form_nonce(true);


            $this->log('db_nonce: ' . var_export($db_nonce, true) . __LINE__);
            $this->log('passed_form_id: ' . var_export($passed_form_id, true) . __LINE__);

            if ( ($db_nonce == false) || ($passed_form_id != $db_nonce) ):

              echo 'Cookies dont match';
              return -515;

            endif;

          endif;

        else:

          echo 'Bad timestamp in cookie';
          return -510;

        endif;


      else:

        // Just check the cookie value set in the config file.
        if ( $passed_val != $this->config_var(['tests', 'cookie_details', 'val']) ):

          echo 'Bad cookie val';
          return -505;

        endif;

      endif;


    else:

        echo 'No cookie found';
        return -500;

    endif;


    return true;

  } // check_cookie()




  /**
   * 
   * @since 0.0.1
   * 
   * @return true
   */
  private function form_field($args = false) {

    $ret_str = '';
    $extra_str = '';

    $default_args = array(
                      'label' => false,
                      'id' => false,
                      'type' => 'text',
                      'name' => '',
                      'value' => '',
                      'wrap' => false,
                      'echo' => true
                    );


    // Set defaults for all passed options
    $args = ( is_array($args) ) ? array_merge($default_args, $args) : $default_args;



    if ( $args['label'] ):

      // If there isn't an ID passed then
      // we need to build one in order to 
      // link the label correctly.
      if ( !$args['id']) :

        $label_id = 'MY_ID_' . ucfirst(strtolower($args['name']));
        $args['id'] = $label_id;

      endif;

      $ret_str .= "<label for=\"{$args['id']}\">{$args['label']}</label>" . PHP_EOL;


    endif;


    // Tack on any additional attributes
    if ( isset($args['extra']) && is_array($args['extra'])):

      foreach ($args['extra'] as $key => $value):

        if ( $value ):

          $extra_str .= $key ."=\"{$value}\" ";

        else:

          $extra_str .= $key . ' ';

        endif;
        
      endforeach;

      $extra_str = trim($extra_str);

    endif;


    // ID
    $id = ( $args['id'] ) ? "id=\"{$args['label']}\"" : '';


    // Build input HTML
    $ret_str .= "<input type=\"{$args['type']}\" name=\"{$args['name']}\" value=\"{$args['value']}\" {$id} {$extra_str} />";



    if ( $args['wrap'] ):

      $wrap_type = ( isset($args['wrap']['type']) ) ? trim($args['wrap']['type']) : 'span' ;
      $wrap_extra = '';


      // Tack on any additional attributes
      if ( isset($args['wrap']['extra']) && is_array($args['wrap']['extra'])):

        foreach ($args['wrap']['extra'] as $key => $value):

          if ( $value ):

            $wrap_extra .= $key ."=\"{$value}\" ";

          else:

            $wrap_extra .= $key . ' ';

          endif;
          
        endforeach;

        $wrap_extra = trim($wrap_extra);

      endif;

      $ret_str = "<{$wrap_type} {$wrap_extra}>" . $ret_str . "</{$wrap_type}>";

    endif;


    // Decide whether we echo the string or return it
    if ($args['echo']):

      echo $ret_str . PHP_EOL;

    else:

      return $ret_str;

    endif;

  } // form_field()



  /**
   * 
   * @since 0.0.1
   * 
   * @return true
   */
  private function respond($response) {

    echo json_encode($response);

    return true;

  } // respond()





function get_client_ip() {

  $ip_address = false;

  if ( isset($_SERVER['HTTP_CLIENT_IP']) ):

    $ip_address = $_SERVER['HTTP_CLIENT_IP'];

  elseif ( isset($_SERVER['HTTP_X_FORWARDED_FOR']) ):

    $ip_address = $_SERVER['HTTP_X_FORWARDED_FOR'];

  elseif ( isset($_SERVER['HTTP_X_FORWARDED']) ):

    $ip_address = $_SERVER['HTTP_X_FORWARDED'];

  elseif ( isset($_SERVER['HTTP_FORWARDED_FOR']) ):

    $ip_address = $_SERVER['HTTP_FORWARDED_FOR'];

  elseif ( isset($_SERVER['HTTP_FORWARDED']) ):

    $ip_address = $_SERVER['HTTP_FORWARDED'];

  elseif ( isset($_SERVER['REMOTE_ADDR']) ):

    $ip_address = $_SERVER['REMOTE_ADDR'];

  endif;


  // Allow localhost if debug is true
  if (EAS_DEBUG):
    $ip_address = ($ip_address = '::1') ? '127.0.0.1' : false;
  endif;


    $this->log('IP: ' . var_export($ip_address, true) . __LINE__);

  return $ip_address;
}






  /**
   * 
   * @since 0.0.1
   * 
   * @return true
   */
  private function cur_time() {

    return $this->cur_timestamp;

  } // cur_time()





  /**
   * 
   * @since 0.0.1
   * 
   * @return bool
   */
  private function is_valid_timestamp($timestamp) {

    return ((string) (int) $timestamp === $timestamp) 
        && ($timestamp <= PHP_INT_MAX)
        && ($timestamp >= ~PHP_INT_MAX);

  } // is_valid_timestamp()




  /**
   * Create or connect to the database and
   * set the class parameter for re-use.
   * 
   * @since 0.0.1
   */
  private function set_db_conn() {

    if ( !file_exists($this->class_dir . '/../' . $this->config_var(['dirs', 'database'])) ) {
      mkdir($this->class_dir . '/../' . $this->config_var(['dirs', 'database']));
    }

    try {
   
      $db_path = 'sqlite:' . $this->class_dir . '/../' . $this->config_var(['dirs', 'database']) . '/' . $this->config_var(['db_details', 'name']);

      // Create (connect to) SQLite database in file
      $file_db = new PDO($db_path);

      // Prevent emulated prepares
      $file_db->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);

      // Set errormode to exceptions
      $file_db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

      $file_db->exec('PRAGMA foreign_keys = ON;');


      if ( !$this->is_db_ready($file_db) ) {

        $this->make_tables($file_db);

      }


      // Set the global database connection property
      $this->db = $file_db;

      $file_db = null;

   
    } catch(PDOException $e) {

      // Print PDOException message
      $this->respond( array('status' => -1, 'msg' => $e->getMessage()) );

    }



  } // set_db_conn()









  /**
   * 
   * @since 0.0.1
   * 
   */
  private function is_db_ready($db) {

    // Try a select statement against the table
    // Run it in try/catch in case PDO is in ERRMODE_EXCEPTION.
    try {

      $result = $db->query("SELECT 1 FROM 'visitors' LIMIT 1");

      // Result is either boolean FALSE (no table found) or PDOStatement Object (table found)
      return $result !== false;

    } catch (Exception $e) {
      // We got an exception == table not found
      return false;
    }


  } // is_db_ready()






  /**
   * 
   * @since 0.0.1
   * 
   */
  private function make_tables($db) {

    try {

      // Create items table
      $db->exec("CREATE TABLE IF NOT EXISTS forms (
                              `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                              `ip` VARCHAR(128) NOT NULL,
                              `form_nonce` VARCHAR(128) NOT NULL,
                              `created` DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL);");

      // Create items table
      $db->exec("CREATE TABLE IF NOT EXISTS visitors (
                              `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                              `ip` VARCHAR(128) NOT NULL,
                              `flag_level` INTEGER,
                              `created` DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL);");

      // Create items table
      $db->exec("CREATE TABLE IF NOT EXISTS attempts (
                              `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                              `visitor_id` INTEGER NOT NULL,
                              `flag_level` INTEGER,
                              `flag_reason` VARCHAR(128) NOT NULL,
                              `created` DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                              FOREIGN KEY(`visitor_id`) REFERENCES `visitors`(`id`) ON DELETE CASCADE);");

      $db->exec("CREATE INDEX attempt_id_index ON attempts(visitor_id);");


      $db->exec("CREATE TRIGGER update_existing_form BEFORE INSERT ON forms
                  WHEN ( (NEW.ip IS NOT NULL) AND
                         ((SELECT COUNT(f.id)
                            FROM `forms` AS f
                            WHERE f.ip = NEW.ip) >= 1) )
                  BEGIN
                    UPDATE `forms` SET `created` = CURRENT_TIMESTAMP,
                                  `form_nonce` = NEW.form_nonce
                                  WHERE `id` = (SELECT COUNT(f.id)
                                              FROM `forms` AS f
                                              WHERE f.ip = NEW.ip);
                    SELECT RAISE (IGNORE);
                  END;");


      $db->exec("CREATE TRIGGER form_ip_check AFTER INSERT ON forms
                  WHEN (LENGTH(NEW.ip) < 7)
                  BEGIN
                    SELECT RAISE (ABORT, 'Must have an IP.');
                  END;");


      $db->exec("CREATE TRIGGER clear_old_forms AFTER INSERT ON forms
                  BEGIN
                     DELETE FROM forms WHERE DATE(`created`) > DATE('now', '-" . $this->config_var(['tests', 'timestamp_details', 'fail_older_than']) . " seconds');
                  END;");
                  
      

                  

      $this->log('tables did not exist. making them now.');

      return true;

    } catch (Exception $e) {

      $this->log('Trouble. ' . $e->getMessage());

      // We got an exception == table not found
      return false;
    }

  } // make_tables()








  /**
   * 
   * @since 0.0.1
   * 
   * @return int|false
   */
  function insert_form_nonce($nonce = false, $ip = false) {

    if ( !$nonce ) { return false; }

    $visitor_ip = ( $ip ) ? $ip : $this->get_client_ip();


    try {

      $sql = "INSERT INTO `forms` (`ip`, `form_nonce`) VALUES(:ip, :nonce)";
      
      $stmt = $this->db->prepare($sql, array(PDO::ATTR_CURSOR => PDO::CURSOR_FWDONLY));

      $stmt->execute(array(':ip' => $visitor_ip, ':nonce' => $nonce));

    } catch ( PDOException $e ) {

      $this->log($e->getMessage());
      return false;

    }

    return $this->db->lastInsertId();

  } // insert_form_nonce()







  /**
   * 
   * @since 0.0.1
   * 
   * @return int|false
   */
  function get_form_nonce($from_db = false, $ip = false) {

    // Try to find a matching row in 
    // the database.
    if ($from_db):

      $visitor_ip = ( $ip ) ? $ip : $this->get_client_ip();


      try {

        $sql = "SELECT `form_nonce` FROM `forms` WHERE ip = '{$visitor_ip}'";
        $stmt = $this->db->prepare($sql);
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_COLUMN);

      } catch ( PDOException $e ) {

        $this->log($e->getMessage());
        return false;

      }

    // Check to see if we have a form nonce
    // in sent along with the form submission.
    else:

      return ( isset($_POST[$this->config_var('form_id_name')]) ) ? trim($_POST[$this->config_var('form_id_name')]) : false;

    endif;

  } // get_form_nonce()








  /**
   * 
   * 
   */
  private function config_var($key) {


    if ( is_array($key) ):

      $temp_conf_array = $this->cfg;

      foreach ($key as $key_name):

        
        
          if ( array_key_exists($key_name, $temp_conf_array) ):
            
            if ( is_array($temp_conf_array[$key_name]) ):
              
              $temp_conf_array = $temp_conf_array[$key_name];

            else:

              $temp_conf_array = $temp_conf_array[$key_name];
              break;

            endif;           

          else:

            return false;

          endif;

      endforeach;

      return $temp_conf_array;

    elseif ( is_string($key) ):

      return ( isset($this->cfg[$key]) ) ? $this->cfg[$key] : false;

    endif;


  } // config_var()







  private function get_config() {

    $conf_filename = "epohs-anti-spam.json";
    $conf_file = false;
    $dir_parent = realpath($this->class_dir . '/..');

    if ( file_exists($this->class_dir . '/' . $conf_filename) ):

      $conf_file = $this->class_dir . '/' . $conf_filename;

    elseif ( file_exists(realpath($dir_parent . '/' . $conf_filename)) ):

      $conf_file = $dir_parent . '/' . $conf_filename;

    else:

      return -1;

    endif;




    // Read JSON file
    $json = file_get_contents($conf_file);

    // Decode JSON
    $json_data = json_decode($json, true);


    // Make sure the file was valid JSON
    if ($json_data === null && json_last_error() !== JSON_ERROR_NONE):
      return $this->cfg_err = -2;
    endif;



    $this->cfg = $json_data;



    if ( ($this->cfg_err = $this->is_config_setup()) !== true ):

      return $this->cfg_err;

    endif;




    return true;


  } // get_config()



  /**
   * Some of the config variables are required.
   * Check those now.
   * 
   * @since 0.0.1
   * 
   * @return bool
   */
  private function is_config_setup() {

    if ( !is_array($this->cfg) ) { return -4; }

    if ( !isset($this->cfg['dirs']['javascript']) ||
         !isset($this->cfg['dirs']['css']) ||
         !isset($this->cfg['tests']) ||
         !isset($this->cfg['use_database']) ) { return -5; }


    return true;

  } // is_config_setup()





  /**
   * Write data to a log file in the current directory.
   * 
   * @since 0.0.1
   * 
   * @param mixed $log_data What you want to write to the log.
   * 
   * @return bool Always true.
   */
  public static function log( $log_data=null ) {

    $activity_log_path = dirname(__FILE__) . "/debug.log";

    $activity_log = $log_data . "\n";

    error_log($activity_log, 3, $activity_log_path);

    return true;

  } // log()








  public function __destruct() {
    // Close file db connection
    $this->db = null;
  }




} // epohs_Anti_Spam



$eas = new epohs_Anti_Spam;
?>