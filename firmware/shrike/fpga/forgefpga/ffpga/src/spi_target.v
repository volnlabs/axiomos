`timescale 1ns/1ps
// Derived from the pinned Vicharak spi_loopback_led SPI target.
// SPDX-License-Identifier: GPL-2.0-only
module spi_target (
    input wire i_clk,
    input wire i_rst_n,
    input wire i_enable,
    input wire i_ss_n,
    input wire i_sck,
    input wire i_mosi,
    output wire o_miso,
    output wire o_miso_oe,
    output wire o_sample_pulse,
    output reg [7:0] o_rx_data,
    output reg o_rx_data_valid,
    input wire [7:0] i_tx_data
);
    reg [2:0] ss_n_sync;
    reg [2:0] sck_sync;
    reg [2:0] bit_count;
    reg [7:0] miso_data;
    reg tx_reload_pending;

    wire sck_rise;
    wire sck_fall;
    wire tx_data_hold;

    assign sck_rise = ~sck_sync[2] & sck_sync[1];
    assign sck_fall = sck_sync[2] & ~sck_sync[1];
    assign tx_data_hold = (ss_n_sync[2] & ~ss_n_sync[1])
                        | ((bit_count == 3'd0) & sck_fall);
    assign o_miso = miso_data[7];
    assign o_miso_oe = ~ss_n_sync[2];
    assign o_sample_pulse = sck_rise;

    always @(posedge i_clk or negedge i_rst_n) begin
        if (!i_rst_n) begin
            ss_n_sync <= 3'b111;
            sck_sync <= 3'b000;
        end else if (i_enable) begin
            ss_n_sync <= {ss_n_sync[1:0], i_ss_n};
            sck_sync <= {sck_sync[1:0], i_sck};
        end else begin
            ss_n_sync <= 3'b111;
            sck_sync <= 3'b000;
        end
    end

    always @(posedge i_clk or negedge i_rst_n) begin
        if (!i_rst_n)
            bit_count <= 3'd0;
        else if (!i_enable || ss_n_sync[1])
            bit_count <= 3'd0;
        else if (sck_rise)
            bit_count <= bit_count + 3'd1;
    end

    always @(posedge i_clk or negedge i_rst_n) begin
        if (!i_rst_n)
            o_rx_data <= 8'h00;
        else if (sck_rise)
            o_rx_data <= {o_rx_data[6:0], i_mosi};
    end

    always @(posedge i_clk or negedge i_rst_n) begin
        if (!i_rst_n)
            o_rx_data_valid <= 1'b0;
        else begin
            o_rx_data_valid <= 1'b0;
            if (sck_rise && bit_count == 3'd7)
                o_rx_data_valid <= 1'b1;
        end
    end

    always @(posedge i_clk or negedge i_rst_n) begin
        if (!i_rst_n) begin
            miso_data <= 8'h00;
            tx_reload_pending <= 1'b0;
        end else if (tx_reload_pending) begin
            // top snapshots status on the synchronized CS edge; reload one
            // clock later, before the protocol's first permitted SCK edge.
            miso_data <= i_tx_data;
            tx_reload_pending <= 1'b0;
        end else if (tx_data_hold) begin
            miso_data <= i_tx_data;
            tx_reload_pending <= ss_n_sync[2] & ~ss_n_sync[1];
        end else if (sck_fall) begin
            miso_data <= {miso_data[6:0], 1'b0};
            tx_reload_pending <= 1'b0;
        end
    end
endmodule
