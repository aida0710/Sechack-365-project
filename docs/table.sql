drop database if exists packet_log;
create database if not exists packet_log;
use packet_log;

-- Create table for storing packet logs
CREATE TABLE packet_log
(
    id                   INT PRIMARY KEY AUTO_INCREMENT,
    arrival_time         DATETIME(6)                          NOT NULL,
    protocol             ENUM ('TCP', 'UDP', 'ICMP', 'Other') NOT NULL,
    ip_version           TINYINT                              NOT NULL,
    src_ip               VARCHAR(45)                          NOT NULL,
    dst_ip               VARCHAR(45)                          NOT NULL,
    src_port             INT UNSIGNED,
    dst_port             INT UNSIGNED,
    ip_header_length     TINYINT UNSIGNED,
    total_length         INT UNSIGNED,
    ttl                  TINYINT UNSIGNED,
    fragment_offset      INT UNSIGNED,
    tcp_seq_num          BIGINT UNSIGNED,
    tcp_ack_num          BIGINT UNSIGNED,
    tcp_window_size      INT UNSIGNED,
    tcp_flags            TINYINT UNSIGNED,
    tcp_data_offset      TINYINT UNSIGNED,
    payload_length       INT UNSIGNED,
    stream_id            VARCHAR(100),
    is_from_client       BOOLEAN,
    tcp_state            ENUM ('SYN_SENT', 'SYN_RECEIVED', 'ESTABLISHED', 'FIN_WAIT_1', 'FIN_WAIT_2', 'CLOSE_WAIT', 'CLOSING', 'LAST_ACK', 'TIME_WAIT', 'CLOSED'),
    application_protocol VARCHAR(45),
    payload              MEDIUMBLOB,
    created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_arrival_time (arrival_time),
    INDEX idx_src_ip (src_ip),
    INDEX idx_dst_ip (dst_ip),
    INDEX idx_src_port (src_port),
    INDEX idx_dst_port (dst_port),
    INDEX idx_protocol (protocol),
    INDEX idx_stream_id (stream_id),
    INDEX idx_application_protocol (application_protocol)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_unicode_ci;