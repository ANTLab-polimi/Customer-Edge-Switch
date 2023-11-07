#!/usr/bin/python3
# the official website documentation of dash and plotly: https://dash.plotly.com/

'''
    This is the web app which read the results stored in the csv file
    and plot them in a graph showing how it is the possible current state of
    the appliances of the industrial environment and its total power
'''

import pandas as pd
import plotly.express as px
import dash
from dash.dependencies import Input, Output
from dash import dcc
from dash import html

excel_file_name = './mains_csv/MainTerminal_PhaseCount.csv'

# Creating a Dash application
app = dash.Dash(__name__)

# with two graphs inside an html Div and a source input which refresh every 10 seconds
app.layout = html.Div([
    dcc.Graph(id='live-graph'),
    dcc.Graph(id='live-graph1'),
    dcc.Interval(
        id='interval-component',
        interval=10*1000,  # Refresh of 10 seconds
        n_intervals=0
    )
])

# the callback function for the server app
@app.callback(
    Output('live-graph', 'figure'),
    Output('live-graph1', 'figure'),
    Input('interval-component', 'n_intervals')
)

# the function that will be launched everytime the server will refresh
def update_graph(n):

    # reading the updated CSV file in order to plot the new data transmitted
    updated_df = pd.read_csv(excel_file_name)
    # filtering the last 20 raws which is about the last minute
    # in this way we drop the compression of the data for a more readable plot
    updated_df = updated_df.tail(20)

    # the first figure to be plotted
    fig = px.line(
    	updated_df,
    	x='Sensor Date Time',
    	y='kW',
    	title='Total Power of the system'
    )

    fig.update_layout(
    	# starting from zero to the current power
    	yaxis=dict(rangemode = 'tozero')
    )

    # the columns to be read from the CSV as appliances
    Y = ['Chip Press', 'Chip Saw', 'High Temperature Oven', 'Soldering Oven', 'Washing Machine']
    
    # the second figure to be plotted
    fig2 = px.line(
    	updated_df,
    	x='Sensor Date Time',
    	y=Y,
    	labels=dict(value="kW"),
    	title='Predicted power of top 5 appliances of the system'
    )
    
    # to set the legend horizontal and not vertical on the right
    fig2.update_layout(
    	legend=dict(
    		orientation="h",
    		yanchor="bottom",
    		y=1.02,
    		xanchor="right",
    		x=1
    	)
    )
    
    return fig, fig2

if __name__ == '__main__':
    app.run_server(debug=True)
